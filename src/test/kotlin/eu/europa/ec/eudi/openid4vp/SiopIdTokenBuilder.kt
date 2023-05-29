package eu.europa.ec.eudi.openid4vp

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.ThumbprintUtils
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet
import java.io.Serializable
import java.security.interfaces.RSAPublicKey
import java.time.Clock
import java.time.Instant
import java.time.ZoneId
import java.util.*

data class HolderInfo(
    val email: String,
    val name: String,
) : Serializable

object SiopIdTokenBuilder {

    fun decode(jwt: String): HolderInfo? = runCatching {
        return with(SignedJWT.parse(jwt).jwtClaimsSet) {
            val email = getStringClaim("email")!!
            val name = getStringClaim("name")!!
            HolderInfo(email = email, name = name)
        }
    }.getOrNull()

    fun decodeAndVerify(jwt: String, walletPublicKey: RSAPublicKey): JWTClaimsSet? = runCatching {
        val verifier = RSASSAVerifier(walletPublicKey)
        val signedJwt = SignedJWT.parse(jwt)

        if (!signedJwt.verify(verifier)) {
            error("Oops signature doesn't match")
        }
        signedJwt.jwtClaimsSet
    }.getOrNull()

    fun randomKey(): RSAKey = RSAKeyGenerator(2048)
        .keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key (optional)
        .keyID(UUID.randomUUID().toString()) // give the key a unique ID (optional)
        .issueTime(Date(System.currentTimeMillis())) // issued-at timestamp (optional)
        .generate()

    fun build(
        request: ResolvedRequestObject.SiopAuthentication,
        holderInfo: HolderInfo,
        walletConfig: WalletOpenId4VPConfig,
        rsaJWK: RSAKey,
        clock: Clock = Clock.systemDefaultZone(),
    ): String {
        fun sign(claimSet: IDTokenClaimsSet): Result<JWT> = runCatching {
            val header = JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK.keyID).build()
            val signedJWT = SignedJWT(header, claimSet.toJWTClaimsSet())
            signedJWT.sign(RSASSASigner(rsaJWK))
            signedJWT
        }

        fun buildJWKThumbprint(): String =
            ThumbprintUtils.compute("SHA-256", rsaJWK).toString()

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

        val subjectJwk = JWKSet(rsaJWK).toPublicJWKSet()

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
            claim("email", holderInfo.email)
            claim("name", holderInfo.name)
            build()
        }

        return sign(IDTokenClaimsSet(claimSet)).getOrThrow().serialize()
    }
}