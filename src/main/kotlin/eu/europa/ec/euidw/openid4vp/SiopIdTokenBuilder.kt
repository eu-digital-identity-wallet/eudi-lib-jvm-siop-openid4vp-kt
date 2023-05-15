package eu.europa.ec.euidw.openid4vp

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.ThumbprintUtils
import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet
import java.time.Clock
import java.time.Instant
import java.time.ZoneId
import java.util.*

object SiopIdTokenBuilder {


    fun build(
        request: ResolvedRequestObject.SiopAuthentication,
        walletConfig: WalletOpenId4VPConfig,
        clock: Clock = Clock.systemDefaultZone()
    ): JWT {

        fun sign(claimSet: IDTokenClaimsSet): Result<JWT> = runCatching {
            val header = JWSHeader.Builder(JWSAlgorithm.RS256).keyID(walletConfig.rsaJWK.keyID).build()
            val signedJWT = SignedJWT(header, claimSet.toJWTClaimsSet())
            signedJWT.sign(RSASSASigner(walletConfig.rsaJWK))
            signedJWT
        }

        fun buildJWKThumbprint(): String =
            ThumbprintUtils.compute("SHA-256", walletConfig.rsaJWK).toString()

        fun buildIssuerClaim(): String =
            when (walletConfig.preferredSubjectSyntaxType) {
                is SubjectSyntaxType.JWKThumbprint -> buildJWKThumbprint()
                is SubjectSyntaxType.DecentralizedIdentifier -> walletConfig.decentralizedIdentifier
            }

        fun computeTokenDates(clock: Clock): Pair<Date, Date> {
            val iat = clock.instant()
            val exp = iat.plusMillis(walletConfig.idTokenTTL.toMillis())
            fun Instant.toDate() = Date.from(atZone(ZoneId.systemDefault()).toInstant())
            return iat.toDate() to exp.toDate()
        }

        val subjectJwk = JWKSet(walletConfig.rsaJWK).toPublicJWKSet()

        val (iat, exp) = computeTokenDates(clock)


        // TODO Consider using IDTokenClaimsSet instead of generic JWTClaimSet
        //  It is more type-safe and expresses by definition IdToken
        val claimSet = with(JWTClaimsSet.Builder()) {
            issuer(buildIssuerClaim())
            subject(buildIssuerClaim()) // By SIOPv2 draft 12 issuer = subject
            audience(request.clientId)
            issueTime(iat)
            expirationTime(exp)
            claim("sub_jwk", subjectJwk.toJSONObject())
            claim("email", walletConfig.holderEmail)
            claim("name", walletConfig.holderName)
            build()
        }

        return sign(IDTokenClaimsSet(claimSet)).getOrThrow()
    }

}