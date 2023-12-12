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
package eu.europa.ec.eudi.openid4vp.internal.request

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.*
import com.nimbusds.jose.shaded.gson.Gson
import com.nimbusds.jose.util.X509CertUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.SupportedClientIdScheme.Preregistered
import eu.europa.ec.eudi.openid4vp.internal.sanOfDNSName
import eu.europa.ec.eudi.openid4vp.internal.sanOfUniformResourceIdentifier
import eu.europa.ec.eudi.openid4vp.internal.success
import io.ktor.client.call.*
import io.ktor.client.request.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import java.security.cert.X509Certificate
import java.text.ParseException

/**
 * Validates a JWT that represents an Authorization Request according to RFC9101
 *
 * @param walletOpenId4VPConfig wallet's configuration
 * @param httpClientFactory a factory to obtain a Ktor http client
 */
internal class JarJwtSignatureValidator(
    private val walletOpenId4VPConfig: WalletOpenId4VPConfig,
    private val httpClientFactory: KtorHttpClientFactory = DefaultHttpClientFactory,
) {

    suspend fun validate(clientId: String, jwt: Jwt): Result<Pair<SupportedClientIdScheme, RequestObject>> =
        runCatching {
            val signedJwt = parse(jwt).getOrThrow()
            when (val validation = doValidate(clientId, signedJwt)) {
                is Either.Left -> throw validation.value.asException()
                is Either.Right -> {
                    val supportedClientIdScheme = validation.value
                    val requestObject = signedJwt.jwtClaimsSet.toType { requestObject(it) }
                    supportedClientIdScheme to requestObject
                }
            }
        }

    private fun parse(jwt: Jwt): Result<SignedJWT> =
        try {
            SignedJWT.parse(jwt).success()
        } catch (pe: ParseException) {
            RequestValidationError.InvalidJarJwt("JAR JWT parse error").asFailure()
        }

    private suspend fun doValidate(
        clientId: String,
        signedJwt: SignedJWT,
    ): Either<AuthorizationRequestError, SupportedClientIdScheme> {
        val untrustedClaimSet = signedJwt.jwtClaimsSet
        val jwtClientId = untrustedClaimSet.getStringClaim("client_id")

        return if (null == jwtClientId) {
            RequestValidationError.MissingClientId.left()
        } else if (clientId != jwtClientId) {
            invalidJarJwt("ClientId mismatch. Found in JAR request $clientId, in JAR Jwt $jwtClientId").left()
        } else {
            val supportedClientIdScheme =
                untrustedClaimSet.getStringClaim("client_id_scheme")
                    ?.let { ClientIdScheme.make(it)?.takeIf { x -> x.supportsJar() } }
                    ?.let { walletOpenId4VPConfig.supportedClientIdScheme(it) }

            when (supportedClientIdScheme) {
                null -> RequestValidationError.UnsupportedClientIdScheme.left()
                is Preregistered -> {
                    validatePreregistered(supportedClientIdScheme, clientId, signedJwt).map { supportedClientIdScheme }
                }

                is SupportedClientIdScheme.X509SanUri -> {
                    validateX509San(
                        supportedClientIdScheme.validator,
                        clientId,
                        signedJwt,
                        X509Certificate::sanOfUniformResourceIdentifier,
                    ).map { supportedClientIdScheme }
                }

                is SupportedClientIdScheme.X509SanDns -> {
                    validateX509San(
                        supportedClientIdScheme.validator,
                        clientId,
                        signedJwt,
                        X509Certificate::sanOfDNSName,
                    ).map { supportedClientIdScheme }
                }

                SupportedClientIdScheme.RedirectUri -> Either.Left(invalidJarJwt("RedirectURI cannot be used with JAR"))
            }
        }
    }

    private suspend fun validatePreregistered(
        supportedClientIdScheme: Preregistered,
        clientId: String,
        signedJwt: SignedJWT,
    ): Either<AuthorizationRequestError, Unit> {
        suspend fun PreregisteredClient.verifySignature() =
            try {
                val jwtProcessor = jwtProcessor(this)
                jwtProcessor.process(signedJwt, null)
                Unit.right()
            } catch (e: JOSEException) {
                throw RuntimeException(e)
            } catch (e: BadJOSEException) {
                invalidJarJwt("Invalid signature ${e.message}").left()
            }

        val trustedClient = supportedClientIdScheme.clients[clientId]
        return trustedClient
            ?.verifySignature()
            ?: invalidJarJwt("Client with client_id $clientId is not pre-registered").left()
    }

    private fun validateX509San(
        trustChainValidator: (List<X509Certificate>) -> Boolean,
        clientId: String,
        signedJwt: SignedJWT,
        subjectAlternativeNames: X509Certificate.() -> Result<List<String>>,
    ): Either<AuthorizationRequestError, Unit> {
        val pubCertChain = signedJwt.header
            ?.x509CertChain
            ?.mapNotNull { X509CertUtils.parse(it.decode()) }
            ?: return invalidJarJwt("Missing or invalid x5c").left()

        val cert = pubCertChain[0]
        val sans = cert.subjectAlternativeNames().getOrElse {
            return invalidJarJwt(
                "x5c misses Subject Alternative Names of type UniformResourceIdentifier",
            ).left()
        }
        if (!sans.contains(clientId)) return invalidJarJwt("ClientId not found in x5c Subject Alternative Names").left()
        if (!trustChainValidator(pubCertChain)) return invalidJarJwt("Untrusted x5c").left()
        return try {
            val jwtProcessor = DefaultJWTProcessor<SecurityContext>().apply {
                jwsTypeVerifier = DefaultJOSEObjectTypeVerifier(
                    JOSEObjectType("oauth-authz-req+jwt"),
                )
                jwsKeySelector = JWSKeySelector { _, _ ->
                    listOf(cert.publicKey)
                }
            }
            jwtProcessor.process(signedJwt, null)
            Unit.right()
        } catch (e: JOSEException) {
            throw RuntimeException(e)
        } catch (e: BadJOSEException) {
            invalidJarJwt("Invalid signature ${e.message}").left()
        }
    }

    private suspend fun jwtProcessor(client: PreregisteredClient): ConfigurableJWTProcessor<SecurityContext> =
        DefaultJWTProcessor<SecurityContext>().also {
            it.jwsTypeVerifier = DefaultJOSEObjectTypeVerifier(
                JOSEObjectType("oauth-authz-req+jwt"),
            )
            it.jwsKeySelector = JWSVerificationKeySelector(
                client.jarSigningAlg.toNimbusJWSAlgorithm(),
                client.jwkSetSource.toNimbus(),
            )
        }

    private suspend fun JwkSetSource.toNimbus(): JWKSource<SecurityContext> {
        val jwkSet = when (this) {
            is JwkSetSource.ByValue -> {
                JWKSet.parse(jwks.toString())
            }

            is JwkSetSource.ByReference -> {
                val unparsed = httpClientFactory().use { client ->
                    client.get(jwksUri.toURL()).body<String>()
                }
                JWKSet.parse(unparsed)
            }
        }
        return ImmutableJWKSet(jwkSet)
    }
}

private fun invalidJarJwt(cause: String): AuthorizationRequestError = RequestValidationError.InvalidJarJwt(cause)

private fun String.toNimbusJWSAlgorithm() = JWSAlgorithm.parse(this)

private fun requestObject(cs: JWTClaimsSet): RequestObject {
    fun Map<String, Any?>.asJsonObject(): JsonObject {
        val jsonStr = Gson().toJson(this)
        return Json.parseToJsonElement(jsonStr).jsonObject
    }

    return with(cs) {
        RequestObject(
            responseType = getStringClaim("response_type"),
            presentationDefinition = getJSONObjectClaim("presentation_definition")?.asJsonObject(),
            presentationDefinitionUri = getStringClaim("presentation_definition_uri"),
            scope = getStringClaim("scope"),
            nonce = getStringClaim("nonce"),
            responseMode = getStringClaim("response_mode"),
            clientIdScheme = getStringClaim("client_id_scheme"),
            clientMetaData = getJSONObjectClaim("client_metadata")?.asJsonObject(),
            clientMetadataUri = getStringClaim("client_metadata_uri"),
            clientId = getStringClaim("client_id"),
            responseUri = getStringClaim("response_uri"),
            redirectUri = getStringClaim("redirect_uri"),
            state = getStringClaim("state"),
            supportedAlgorithm = getStringClaim("supported_algorithm"),
            idTokenType = getStringClaim("id_token_type"),
        )
    }
}

private sealed interface Either<out L, out R> {
    data class Left<L, R>(val value: L) : Either<L, R>
    data class Right<L, R>(val value: R) : Either<L, R>

    fun <R1> map(f: (R) -> R1): Either<L, R1> = when (this) {
        is Left<L, R> -> Left(value)
        is Right<L, R> -> Right(f(value))
    }
}

private fun <L, R> L.left(): Either.Left<L, R> = Either.Left(this)
private fun <L, R> R.right(): Either.Right<L, R> = Either.Right(this)
