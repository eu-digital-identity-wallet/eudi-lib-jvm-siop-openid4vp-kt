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
import com.nimbusds.jose.proc.BadJOSEException
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.shaded.gson.Gson
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.internal.success
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import java.text.ParseException

/**
 * The outcome of validating a [Jwt] that represents an
 * Authorization Request according to RFC9101
 *
 * @param CS the type that represents the set of claims of a valid JWT
 */
internal sealed interface JarJwtValidation<out CS> {

    /**
     * Indicates a parsing exception
     */
    object NotJwt : JarJwtValidation<Nothing> {
        override fun toString(): String {
            return "NotJwt"
        }
    }

    /**
     * Indicates that JWT can be parsed but signature is invalid
     */
    object InvalidSignature : JarJwtValidation<Nothing> {
        override fun toString(): String {
            return "InvalidSignature"
        }
    }

    data class ValidSignature<CS>(val jwtClaimSet: CS) : JarJwtValidation<CS>

    /**
     * Indicates that the client (verifier) that placed the authorization
     * request is not trusted by the wallet
     */
    object UntrustedClient : JarJwtValidation<Nothing> {
        override fun toString(): String {
            return "UntrustedClient"
        }
    }

    /**
     * Maps to another way of representing the set of claims of a valid JWT
     * @param f the mapping function
     * @param CS2 the type of representing the set of claims of a valid JWT
     * @return another sealed hierarchy of outcomes that uses the [CS2]
     */
    fun <CS2> map(f: (CS) -> CS2): JarJwtValidation<CS2> = when (this) {
        is ValidSignature -> ValidSignature(f(this.jwtClaimSet))
        is InvalidSignature -> InvalidSignature
        NotJwt -> NotJwt
        UntrustedClient -> UntrustedClient
    }
}

/**
 * Validates a JWT that represents an Authorization Request according to RFC9101
 *
 * @param CS the type that represents the set of claims of a valid JWT
 */
internal fun interface JarJwtSignatureValidator<CS> {

    suspend fun validate(clientId: String, jwt: Jwt): JarJwtValidation<CS>

    suspend fun validateOrError(clientId: String, jwt: Jwt): Result<CS> =
        when (val v = validate(clientId, jwt)) {
            is JarJwtValidation.ValidSignature -> v.jwtClaimSet.success()
            JarJwtValidation.InvalidSignature -> RequestValidationError.InvalidJarJwt(v.toString()).asFailure()
            JarJwtValidation.NotJwt -> RequestValidationError.InvalidJarJwt(v.toString()).asFailure()
            JarJwtValidation.UntrustedClient -> RequestValidationError.InvalidJarJwt(v.toString()).asFailure()
        }

    fun <CS2> map(f: (CS) -> CS2): JarJwtSignatureValidator<CS2> = JarJwtSignatureValidator { clientId, jwt ->
        this.validate(clientId, jwt).map(f)
    }

    companion object {

        /**
         * Creates a [JarJwtValidation] using the [walletOpenId4VPConfig]
         *
         * @param walletOpenId4VPConfig the wallet configuration
         *
         */
        fun forConfig(walletOpenId4VPConfig: WalletOpenId4VPConfig): JarJwtSignatureValidator<RequestObject> =
            when (val supportedClientIdScheme = walletOpenId4VPConfig.supportedClientIdScheme) {
                SupportedClientIdScheme.IsoX509 -> NonValidating
                is SupportedClientIdScheme.Preregistered ->
                    if (supportedClientIdScheme.preregisteredClients.isEmpty()) {
                        NonValidating
                    } else {
                        PreregisteredClientJwtValidator(supportedClientIdScheme)
                    }
            }.map { requestObject(it) }

        private object NonValidating : JarJwtSignatureValidator<JWTClaimsSet> {

            override suspend fun validate(clientId: String, jwt: Jwt): JarJwtValidation<JWTClaimsSet> = try {
                val signedJwt = SignedJWT.parse(jwt)
                JarJwtValidation.ValidSignature(signedJwt.jwtClaimsSet)
            } catch (pe: ParseException) {
                JarJwtValidation.NotJwt
            }
        }

        private class PreregisteredClientJwtValidator(
            private val preregistered: SupportedClientIdScheme.Preregistered,
        ) : JarJwtSignatureValidator<JWTClaimsSet> {

            override suspend fun validate(clientId: String, jwt: Jwt): JarJwtValidation<JWTClaimsSet> {
                val preregisteredClientMetaData = preregistered.clients[clientId]
                return if (preregisteredClientMetaData == null) {
                    return JarJwtValidation.UntrustedClient
                } else {
                    try {
                        val signedJwt = SignedJWT.parse(jwt)
                        val jwtProcessor = jwtProcessor(preregisteredClientMetaData)
                        val jwtClaimsSet = jwtProcessor.process(signedJwt, null)
                        JarJwtValidation.ValidSignature(jwtClaimsSet)
                    } catch (e: ParseException) {
                        JarJwtValidation.NotJwt
                    } catch (e: JOSEException) {
                        throw RuntimeException(e)
                    } catch (e: BadJOSEException) {
                        JarJwtValidation.InvalidSignature
                    }
                }
            }
        }
    }
}

private fun jwtProcessor(client: PreregisteredClient): ConfigurableJWTProcessor<SecurityContext> =
    DefaultJWTProcessor<SecurityContext>().also {
        it.jwsTypeVerifier = DefaultJOSEObjectTypeVerifier(
            JOSEObjectType("oauth-authz-req+jwt"),
        )
        it.jwsKeySelector = JWSVerificationKeySelector(
            client.jarSigningAlg.toNimbusJWSAlgorithm(),
            client.jwkSetSource.toNimbus(),
        )
        it.setJWTClaimsSetVerifier(
            DefaultJWTClaimsVerifier(
                JWTClaimsSet.Builder().claim("client_id", client.clientId).build(),
                setOf("scope", "state", "nonce", "response_type", "response_mode"),
            ),
        )
    }

private fun String.toNimbusJWSAlgorithm() = JWSAlgorithm.parse(this)

internal fun JwkSetSource.toNimbus(): JWKSource<SecurityContext> {
    val jwkSet = when (this) {
        is JwkSetSource.ByValue -> {
            JWKSet.parse(jwks.toString())
        }

        is JwkSetSource.ByReference -> {
            JWKSet.load(jwksUri.toURL())
        }
    }
    return ImmutableJWKSet(jwkSet)
}

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
