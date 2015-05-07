package org.http4s
package server
package middleware
package authentication

import java.security.SecureRandom
import java.math.BigInteger
import java.util.Date
import org.http4s.headers.Authorization
import scala.collection.mutable.HashMap
import scala.concurrent.duration._

import scalaz.concurrent.Task

/**
 * Provides Digest Authentication from RFC 2617. Note that this class creates a new thread
 * on creation to clean up stale nonces. Please call {@link shutdown()} when the object is not
 * used anymore to kill this thread.
 * @param realm The realm used for authentication purposes.
 * @param store A partial function mapping (realm, user) to the
 *              appropriate password.
 * @param nonceCleanupInterval Interval (in milliseconds) at which stale
 *                             nonces should be cleaned up.
 * @param nonceStaleTime Amount of time (in milliseconds) after which a nonce
 *                       is considered stale (i.e. not used for authentication
 *                       purposes anymore).
 * @param nonceBits The number of random bits a nonce should consist of.
 */
class DigestAuthentication(realm: String, store: AuthenticationStore, nonceCleanupInterval: Duration = 3600.seconds, nonceStaleTime: Duration = 3600.seconds, nonceBits: Int = 160) extends Authentication {
  private val nonceKeeper = new NonceKeeper(nonceStaleTime.toMillis, nonceCleanupInterval.toMillis, nonceBits)

  /** Side-effect of running the returned task: If req contains a valid
    * AuthorizationHeader, the corresponding nonce counter (nc) is increased.
    */
  protected def getChallenge(req: Request) = {
    def paramsToChallenge(params: Map[String, String]) = Some(Challenge("Digest", realm, params))
    checkAuth(req).flatMap(_ match {
      case OK         => Task.now(None)
      case StaleNonce => getChallengeParams(true).map(paramsToChallenge)
      case _          => getChallengeParams(false).map(paramsToChallenge)
    })
  }

  private case object StaleNonce extends AuthReply

  private case object BadNC extends AuthReply

  private case object WrongResponse extends AuthReply

  private case object BadParameters extends AuthReply

  private def checkAuth(req: Request) = Task {
    req.headers.get(Authorization) match {
      case None => NoAuthorizationHeader
      case Some(auth) => auth.credentials match {
        case GenericCredentials(AuthScheme.Digest, params) =>
          checkAuthParams(req, params)
        case _ => NoCredentials
      }
    }
  }

  private def getChallengeParams(staleNonce: Boolean) = Task {
    val nonce = nonceKeeper.newNonce()
    val m = Map("qop" -> "auth", "nonce" -> nonce)
    if (staleNonce)
      m + ("stale" -> "TRUE")
    else
      m
  }

  private def checkAuthParams(req: Request, params: Map[String, String]): AuthReply = {
    if (!(Set("realm", "nonce", "nc", "username", "cnonce", "qop") subsetOf params.keySet))
      return BadParameters

    val method = req.method.toString
    val uri = req.uri.toString

    if (params.get("realm") != Some(realm))
      return BadParameters

    val nonce = params("nonce")
    val nc = params("nc")
    nonceKeeper.receiveNonce(nonce, Integer.parseInt(nc, 16)) match {
      case NonceKeeper.StaleReply => StaleNonce
      case NonceKeeper.BadNCReply => BadNC
      case NonceKeeper.OKReply =>
        if (!store.isDefinedAt((realm, params("username"))))
          UserUnknown
        else
          store((realm, params("username"))) match {
            case password => {
              val resp = DigestUtil.computeResponse(method, params("username"), realm, password, uri, nonce, nc, params("cnonce"), params("qop"))
              if (resp == params("response"))
                OK
              else
                WrongResponse
            }
          }
    }
  }
}

private[authentication] class Nonce(val created: Date, var nc: Int, val data: String)

private[authentication] object Nonce {
  val random = new SecureRandom()

  private def getRandomData(bits: Int) = new BigInteger(bits, random).toString(16)

  def apply(bits: Int) = {
    new Nonce(new Date(), 0, getRandomData(bits))
  }
}

private[authentication] object NonceKeeper {

  sealed abstract class Reply

  case object StaleReply extends Reply

  case object OKReply extends Reply

  case object BadNCReply extends Reply

}

/**
 * A thread-safe class used to manage a database of nonces.
 *
 * @param staleTimeout Amount of time (in milliseconds) after which a nonce
 *                     is considered stale (i.e. not used for authentication
 *                     purposes anymore).
 * @param bits The number of random bits a nonce should consist of.
 */
private[authentication] class NonceKeeper(staleTimeout: Long, nonceCleanupInterval: Long, bits: Int) {
  require(bits > 0, "Please supply a positive integer for bits.")
  private val nonces = new HashMap[String, Nonce]
  private var lastCleanup = System.currentTimeMillis()

  /**
   * Removes nonces that are older than staleTimeout
   */
  private def checkStale() = {
    val d = System.currentTimeMillis()
    if (d - lastCleanup > nonceCleanupInterval) {
      nonces.retain{ case (_,n) => staleTimeout > d - n.created.getTime() }
      lastCleanup = d
    }
  }

  /**
   * Get a fresh nonce in form of a {@link String}.
   * @return A fresh nonce.
   */
  def newNonce() = {
    var n: Nonce = null
    nonces.synchronized {
      checkStale()
      do {
        n = Nonce(bits)
      } while (nonces.contains(n.data))
      nonces += (n.data -> n)
    }
    n.data
  }

  /**
   * Checks if the nonce {@link data} is known and the {@link nc} value is
   * correct. If this is so, the nc value associated with the nonce is increased
   * and the appropriate status is returned.
   * @param data The nonce.
   * @param nc The nonce counter.
   * @return A reply indicating the status of (data, nc).
   */
  def receiveNonce(data: String, nc: Int): NonceKeeper.Reply =
    nonces.synchronized {
      checkStale()
      nonces.get(data) match {
        case None => NonceKeeper.StaleReply
        case Some(n) => {
          if (nc > n.nc) {
            n.nc = n.nc + 1
            NonceKeeper.OKReply
          } else
            NonceKeeper.BadNCReply
        }
      }
    }
}
