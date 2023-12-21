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

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import eu.europa.ec.eudi.prex.ClaimFormat
import eu.europa.ec.eudi.prex.PresentationDefinition
import eu.europa.ec.eudi.prex.SupportedClaimFormat
import kotlinx.serialization.json.JsonObject
import java.net.URI
import java.security.cert.X509Certificate

sealed interface JwkSetSource {
    data class ByValue(val jwks: JsonObject) : JwkSetSource
    data class ByReference(val jwksUri: URI) : JwkSetSource
}

data class PreregisteredClient(
    val clientId: String,
    val jarSigningAlg: String,
    val jwkSetSource: JwkSetSource,
)

sealed interface SupportedClientIdScheme {
    val scheme: ClientIdScheme
        get() = when (this) {
            is Preregistered -> ClientIdScheme.PreRegistered
            is X509SanUri -> ClientIdScheme.X509_SAN_URI
            is X509SanDns -> ClientIdScheme.X509_SAN_DNS
            RedirectUri -> ClientIdScheme.RedirectUri
        }

    data class Preregistered(val clients: Map<String, PreregisteredClient>) : SupportedClientIdScheme {
        constructor(vararg clients: PreregisteredClient) : this(clients.toList().associateBy { it.clientId })
    }

    data class X509SanUri(val validator: (List<X509Certificate>) -> Boolean) : SupportedClientIdScheme

    data class X509SanDns(val validator: (List<X509Certificate>) -> Boolean) : SupportedClientIdScheme

    data object RedirectUri : SupportedClientIdScheme
}

data class SiopOpenId4VPConfig(
    val supportedClientIdSchemes: List<SupportedClientIdScheme>,
    val vpConfiguration: VPConfiguration,
    val jarmConfiguration: JarmConfiguration,
)

data class VPConfiguration(
    val vpFormatsSupported: List<SupportedClaimFormat<in ClaimFormat>>,
    val presentationDefinitionUriSupported: Boolean,
    val knownPresentationDefinitionsPerScope: Map<String, PresentationDefinition> = emptyMap(),
)

data class JarmConfiguration(
    val holderId: String,
    val authorizationResponseSigners: List<AuthorizationResponseSigner>,
    val authorizationEncryptionAlgValuesSupported: List<JWEAlgorithm>,
    val authorizationEncryptionEncValuesSupported: List<EncryptionMethod>,
)

fun SiopOpenId4VPConfig.supportedClientIdScheme(scheme: ClientIdScheme): SupportedClientIdScheme? =
    supportedClientIdSchemes.firstOrNull { it.scheme == scheme }

fun SiopOpenId4VPConfig.supportedResponseSigner(signingAlgorithm: JWSAlgorithm): AuthorizationResponseSigner? =
    jarmConfiguration.authorizationResponseSigners.firstOrNull { it.supportedJWSAlgorithms().contains(signingAlgorithm) }
