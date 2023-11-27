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
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.SupportedClientIdScheme.IsoX509
import eu.europa.ec.eudi.openid4vp.SupportedClientIdScheme.Preregistered
import eu.europa.ec.eudi.openid4vp.internal.success
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import java.text.ParseException

/**
 * Validates a JWT that represents an Authorization Request according to RFC9101
 *
 * @param walletOpenId4VPConfig wallet's configuration
 */
internal class JarJwtSignatureValidator(
    private val walletOpenId4VPConfig: WalletOpenId4VPConfig,
) {

    fun validate(clientId: String, jwt: Jwt): Result<RequestObject> = runCatching {
        val signedJwt = parse(jwt).getOrThrow()
        val error = doValidate(clientId, signedJwt)
        if (null == error) signedJwt.jwtClaimsSet.toType { requestObject(it) }
        else throw error.asException()
    }

    private fun parse(jwt: Jwt): Result<SignedJWT> =
        try {
            SignedJWT.parse(jwt).success()
        } catch (pe: ParseException) {
            RequestValidationError.InvalidJarJwt("JAR JWT parse error").asFailure()
        }

    private fun doValidate(clientId: String, signedJwt: SignedJWT): AuthorizationRequestError? {
        val untrustedClaimSet = signedJwt.jwtClaimsSet
        val jwtClientId = untrustedClaimSet.getStringClaim("client_id")

        return if (null == jwtClientId) {
            RequestValidationError.MissingClientId
        } else if (clientId != jwtClientId) {
            invalidJarJwt("ClientId mismatch. Found in JAR request $clientId, in JAR Jwt $jwtClientId")
        } else {
            val supportedClientIdScheme =
                untrustedClaimSet.getStringClaim("client_id_scheme")
                    ?.let { ClientIdScheme.make(it) }
                    ?.let { walletOpenId4VPConfig.supportedClientIdScheme(it) }
            //
            // Currently is not defined how to
            // process client_id when the scheme is IsoX509 or not provided
            // Thus, we don't validate the signature
            //
            when (supportedClientIdScheme) {
                null -> null
                IsoX509 -> null
                is Preregistered -> validatePreregistered(supportedClientIdScheme, clientId, signedJwt)
            }
        }
    }
}

private fun invalidJarJwt(cause: String): AuthorizationRequestError = RequestValidationError.InvalidJarJwt(cause)

private fun validatePreregistered(
    supportedClientIdScheme: Preregistered,
    clientId: String,
    signedJwt: SignedJWT,
): AuthorizationRequestError? {
    fun PreregisteredClient.verifySignature() =
        try {
            val jwtProcessor = jwtProcessor(this)
            jwtProcessor.process(signedJwt, null)
            null
        } catch (e: JOSEException) {
            throw RuntimeException(e)
        } catch (e: BadJOSEException) {
            invalidJarJwt("Invalid signature ${e.message}")
        }

    val trustedClient = supportedClientIdScheme.clients[clientId]
    return if (null == trustedClient) invalidJarJwt("Client with client_id $clientId is not pre-registered")
    else trustedClient.verifySignature()
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
