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
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import eu.europa.ec.eudi.prex.ClaimFormat
import eu.europa.ec.eudi.prex.PresentationDefinition
import eu.europa.ec.eudi.prex.SupportedClaimFormat
import kotlinx.serialization.json.JsonObject
import java.net.URI
import java.time.Duration

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
            is IsoX509 -> ClientIdScheme.ISO_X509
        }

    data class Preregistered(val clients: Map<String, PreregisteredClient>) : SupportedClientIdScheme

    data object IsoX509 : SupportedClientIdScheme
}

data class WalletOpenId4VPConfig(
    val subjectSyntaxTypesSupported: List<SubjectSyntaxType>,
    val preferredSubjectSyntaxType: SubjectSyntaxType,
    val decentralizedIdentifier: String,
    val idTokenTTL: Duration,
    val presentationDefinitionUriSupported: Boolean,
    val signingKey: JWK,
    val signingKeySet: JWKSet,
    val supportedClientIdSchemes: List<SupportedClientIdScheme>,
    val vpFormatsSupported: List<SupportedClaimFormat<in ClaimFormat>>,
    val knownPresentationDefinitionsPerScope: Map<String, PresentationDefinition> = emptyMap(),
    val authorizationSigningAlgValuesSupported: List<JWSAlgorithm>,
    val authorizationEncryptionAlgValuesSupported: List<JWEAlgorithm>,
    val authorizationEncryptionEncValuesSupported: List<EncryptionMethod>,
)

fun WalletOpenId4VPConfig.supportedClientIdScheme(scheme: ClientIdScheme): SupportedClientIdScheme? =
    supportedClientIdSchemes.firstOrNull { it.scheme == scheme }
