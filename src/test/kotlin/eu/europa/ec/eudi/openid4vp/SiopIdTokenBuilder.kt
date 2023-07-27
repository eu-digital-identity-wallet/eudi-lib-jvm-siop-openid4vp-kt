/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.openid4vp

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.ThumbprintUtils
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import com.nimbusds.oauth2.sdk.id.Audience
import com.nimbusds.oauth2.sdk.id.Issuer
import com.nimbusds.oauth2.sdk.id.Subject
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet
import java.io.Serializable
import java.time.Clock
import java.time.Instant
import java.time.ZoneId
import java.util.*

data class HolderInfo(
    val email: String,
    val name: String,
) : Serializable

object SiopIdTokenBuilder {

    fun decodeAndVerify(jwt: String, walletPubKey: RSAKey): Result<IDTokenClaimsSet> = runCatching {
        val jwtProcessor = DefaultJWTProcessor<SecurityContext>().also {
            it.jwsTypeVerifier = DefaultJOSEObjectTypeVerifier(JOSEObjectType.JWT)
            val jwsAlg = JWSAlgorithm.RS256
            val jwkSet: JWKSource<SecurityContext> = ImmutableJWKSet(JWKSet(walletPubKey))
            it.jwsKeySelector = JWSVerificationKeySelector(
                jwsAlg,
                jwkSet,
            )
        }
        val claimsSet = jwtProcessor.process(jwt, null)
        IDTokenClaimsSet(claimsSet)
    }

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
            val header = JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(rsaJWK.keyID)
                .type(JOSEObjectType.JWT)
                .build()
            val signedJWT = SignedJWT(header, claimSet.toJWTClaimsSet())
            signedJWT.sign(RSASSASigner(rsaJWK))
            signedJWT
        }

        fun buildJWKThumbprint(): String = ThumbprintUtils.compute("SHA-256", rsaJWK).toString()

        fun buildIssuerClaim(): String = when (walletConfig.preferredSubjectSyntaxType) {
            is SubjectSyntaxType.JWKThumbprint -> buildJWKThumbprint()
            is SubjectSyntaxType.DecentralizedIdentifier -> walletConfig.decentralizedIdentifier
        }

        fun computeTokenDates(clock: Clock): Pair<Date, Date> {
            val iat = clock.instant()
            val exp = iat.plusMillis(walletConfig.idTokenTTL.toMillis())
            fun Instant.toDate() = Date.from(atZone(ZoneId.systemDefault()).toInstant())
            return iat.toDate() to exp.toDate()
        }

        val (iat, exp) = computeTokenDates(clock)

        return with(
            IDTokenClaimsSet(
                Issuer(buildIssuerClaim()),
                Subject(buildIssuerClaim()),
                listOf(request.clientId).map { Audience(it) },
                exp,
                iat,
            ),
        ) {
            subjectJWK = rsaJWK.toPublicJWK()
            setClaim("email", holderInfo.email)
            setClaim("name", holderInfo.name)

            sign(this).getOrThrow().serialize()
        }
    }
}
