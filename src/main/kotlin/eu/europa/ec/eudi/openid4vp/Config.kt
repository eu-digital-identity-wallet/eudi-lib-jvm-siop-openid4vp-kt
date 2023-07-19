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

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import eu.europa.ec.eudi.prex.ClaimFormat
import eu.europa.ec.eudi.prex.PresentationDefinition
import eu.europa.ec.eudi.prex.SupportedClaimFormat
import kotlinx.serialization.json.JsonObject
import java.net.URI
import java.time.Duration
import java.util.*

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

    object IsoX509 : SupportedClientIdScheme {
        override fun toString(): String {
            return "IsoX509"
        }
    }
}

data class WalletOpenId4VPConfig(
    val subjectSyntaxTypesSupported: List<SubjectSyntaxType>,
    val preferredSubjectSyntaxType: SubjectSyntaxType = SubjectSyntaxType.JWKThumbprint,
    val decentralizedIdentifier: String = "DID:example:12341512#$",
    val idTokenTTL: Duration = Duration.ofMinutes(10),
    val presentationDefinitionUriSupported: Boolean = false,
    val signingKey: RSAKey = RSAKeyGenerator(2048)
        .keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key (optional)
        .keyID(UUID.randomUUID().toString()) // give the key a unique ID (optional)
        .issueTime(Date(System.currentTimeMillis())) // issued-at timestamp (optional)
        .generate(),
    val signingKeySet: JWKSet = JWKSet(signingKey),
    val supportedClientIdSchemes: List<SupportedClientIdScheme>,
    val vpFormatsSupported: List<SupportedClaimFormat<in ClaimFormat>>,
    val knownPresentationDefinitionsPerScope: Map<String, PresentationDefinition> = emptyMap(),
)

fun WalletOpenId4VPConfig.supportedClientIdScheme(scheme: ClientIdScheme): SupportedClientIdScheme? =
    supportedClientIdSchemes.firstOrNull { it.scheme == scheme }
