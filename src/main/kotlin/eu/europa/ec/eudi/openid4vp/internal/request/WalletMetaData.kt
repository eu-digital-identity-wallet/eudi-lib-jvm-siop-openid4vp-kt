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

import eu.europa.ec.eudi.openid4vp.SiopOpenId4VPConfig
import eu.europa.ec.eudi.openid4vp.encryptionConfig
import eu.europa.ec.eudi.openid4vp.signingConfig
import kotlinx.serialization.json.*

private const val CLIENT_ID_SCHEMES_SUPPORTED = "client_id_schemes_supported"
private const val REQUEST_OBJECT_SIGNING_ALG_VALUES_SUPPORTED = "request_object_signing_alg_values_supported"
private const val VP_FORMATS_SUPPORTED = "vp_formats_supported"
private const val PRESENTATION_DEFINITION_URI_SUPPORTED = "presentation_definition_uri_supported"
private const val AUTHORIZATION_ENCRYPTION_ALG_VALUES_SUPPORTED = "authorization_encryption_alg_values_supported"
private const val AUTHORIZATION_ENCRYPTION_ENC_VALUES_SUPPORTED = "authorization_encryption_enc_values_supported"

internal fun walletMetaData(cfg: SiopOpenId4VPConfig): JsonObject =
    buildJsonObject {
        val vpFormats =
            VpFormats.make(cfg.vpConfiguration.vpFormats).let(Json.Default::encodeToJsonElement)
        put(VP_FORMATS_SUPPORTED, vpFormats)

        cfg.jarmConfiguration.encryptionConfig()?.let { encryptionConfig ->
            putJsonArray(AUTHORIZATION_ENCRYPTION_ALG_VALUES_SUPPORTED) {
                encryptionConfig.supportedAlgorithms.forEach { alg -> add(alg.name) }
            }
            putJsonArray(AUTHORIZATION_ENCRYPTION_ENC_VALUES_SUPPORTED) {
                encryptionConfig.supportedMethods.forEach { method -> add(method.name) }
            }
        }

        cfg.jarmConfiguration.signingConfig()?.let { signingConfig ->
            val algs = signingConfig.signer.supportedJWSAlgorithms().orEmpty()
            if (algs.isNotEmpty()) {
                putJsonArray(REQUEST_OBJECT_SIGNING_ALG_VALUES_SUPPORTED) {
                    algs.forEach { alg -> add(alg.name) }
                }
            }
        }
        put(PRESENTATION_DEFINITION_URI_SUPPORTED, cfg.vpConfiguration.presentationDefinitionUriSupported)

        putJsonArray(CLIENT_ID_SCHEMES_SUPPORTED) {
            cfg.supportedClientIdSchemes.forEach { supportedClientIdScheme ->
                add(supportedClientIdScheme.scheme().value())
            }
        }
    }
