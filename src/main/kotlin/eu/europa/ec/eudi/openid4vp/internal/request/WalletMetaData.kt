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

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import eu.europa.ec.eudi.openid4vp.EncryptionRequirement
import eu.europa.ec.eudi.openid4vp.SiopOpenId4VPConfig
import eu.europa.ec.eudi.openid4vp.internal.toJsonObject
import kotlinx.serialization.json.*

private const val REQUEST_OBJECT_SIGNING_ALG_VALUES_SUPPORTED = "request_object_signing_alg_values_supported"
private const val JWKS = "jwks"
private const val AUTHORIZATION_ENCRYPTION_ALG_VALUES_SUPPORTED = "authorization_encryption_alg_values_supported"
private const val AUTHORIZATION_ENCRYPTION_ENC_VALUES_SUPPORTED = "authorization_encryption_enc_values_supported"

private const val PRESENTATION_DEFINITION_URI_SUPPORTED = "presentation_definition_uri_supported"
private const val CLIENT_ID_SCHEMES_SUPPORTED = "client_id_schemes_supported"
private const val VP_FORMATS_SUPPORTED = "vp_formats_supported"
private const val RESPONSE_TYPES_SUPPOERTED = "response_types_supported"
private const val RESPONSE_MODES_SUPPORTED = "response_modes_supported"

internal fun walletMetaData(cfg: SiopOpenId4VPConfig, keys: List<JWK>): JsonObject =
    buildJsonObject {
        //
        // Authorization Request signature and encryption parameters
        // Uses properties defined in JAR and JARM specs
        // https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#name-request-uri-method-post
        //

        // Signature
        putJsonArray(REQUEST_OBJECT_SIGNING_ALG_VALUES_SUPPORTED) {
            cfg.jarConfiguration.supportedAlgorithms.forEach { alg -> add(alg.name) }
        }

        // Encryption
        cfg.jarConfiguration.supportedRequestUriMethods.isPostSupported()?.let { requestUriMethodPost ->
            val jarEncryption = requestUriMethodPost.jarEncryption
            if (jarEncryption is EncryptionRequirement.Required && keys.isNotEmpty()) {
                put(JWKS, JWKSet(keys).toJSONObject(true).toJsonObject())
                putJsonArray(AUTHORIZATION_ENCRYPTION_ALG_VALUES_SUPPORTED) {
                    jarEncryption.supportedEncryptionAlgorithms.forEach { alg -> add(alg.name) }
                }
                putJsonArray(AUTHORIZATION_ENCRYPTION_ENC_VALUES_SUPPORTED) {
                    jarEncryption.supportedEncryptionMethods.forEach { method -> add(method.name) }
                }
            }
        }

        //
        // OpenIdVP
        //
        put(PRESENTATION_DEFINITION_URI_SUPPORTED, cfg.vpConfiguration.presentationDefinitionUriSupported)

        val vpFormats =
            VpFormatsTO.make(cfg.vpConfiguration.vpFormats).let(Json.Default::encodeToJsonElement)
        put(VP_FORMATS_SUPPORTED, vpFormats)
        putJsonArray(CLIENT_ID_SCHEMES_SUPPORTED) {
            cfg.supportedClientIdSchemes.forEach { supportedClientIdScheme ->
                add(supportedClientIdScheme.scheme().value())
            }
        }
        putJsonArray(RESPONSE_TYPES_SUPPOERTED) {
            add("vp_token")
            add("id_token")
            add("vp_token id_token")
        }

        // TODO Investigate is this should be hardcoded, or
        //  if we should add an option to cfg
        putJsonArray(RESPONSE_MODES_SUPPORTED) {
            add("direct_post")
            add("direct_post.jwt")
        }
    }
