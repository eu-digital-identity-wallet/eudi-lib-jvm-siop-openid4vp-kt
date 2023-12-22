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
import java.io.Serializable
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

sealed interface JarmConfiguration : Serializable {

    fun supportedSigningAlgorithms(): List<JWSAlgorithm> = when (this) {
        is Encryption -> emptyList()
        NotSupported -> emptyList()
        is Signing -> supportedAlgorithms
        is SigningAndEncryption -> signing.supportedAlgorithms
    }

    fun supportedEncryptionAlgorithms(): List<JWEAlgorithm> = when (this) {
        is Encryption -> supportedAlgorithms
        NotSupported -> emptyList()
        is Signing -> emptyList()
        is SigningAndEncryption -> encryption.supportedAlgorithms
    }

    fun supportedEncryptionMethods(): List<EncryptionMethod> = when (this) {
        is Encryption -> supportedEncryptionMethods
        NotSupported -> emptyList()
        is Signing -> emptyList()
        is SigningAndEncryption -> encryption.supportedEncryptionMethods
    }

    data class Signing(
        val holderId: String,
        val supportedAlgorithms: List<JWSAlgorithm>,
    ) : JarmConfiguration {
        init {
            require(supportedAlgorithms.isNotEmpty()) { "At least a algorithm must be provided" }
        }
    }

    data class Encryption(
        val holderId: String,
        val supportedAlgorithms: List<JWEAlgorithm>,
        val supportedEncryptionMethods: List<EncryptionMethod>,
    ) : JarmConfiguration {
        init {
            require(supportedAlgorithms.isNotEmpty()) { "At least an encryption algorithm must be provided" }
            require(supportedEncryptionMethods.isNotEmpty()) { "At least an encryption method must be provided" }
        }
    }

    data class SigningAndEncryption(val signing: Signing, val encryption: Encryption) : JarmConfiguration {

        constructor(
            holderId: String,
            supportedSigningAlgorithms: List<JWSAlgorithm>,
            supportedEncryptionAlgorithms: List<JWEAlgorithm>,
            supportedEncryptionMethods: List<EncryptionMethod>,
        ) : this(
            Signing(holderId, supportedSigningAlgorithms),
            Encryption(holderId, supportedEncryptionAlgorithms, supportedEncryptionMethods),
        )

        init {
            require(signing.holderId == encryption.holderId)
        }
    }

    data object NotSupported : JarmConfiguration {
        private fun readResolve(): Any = NotSupported
    }
}

internal fun SiopOpenId4VPConfig.supportedClientIdScheme(scheme: ClientIdScheme): SupportedClientIdScheme? =
    supportedClientIdSchemes.firstOrNull { it.scheme == scheme }

internal fun SiopOpenId4VPConfig.holderId(): String? = when (val cfg = jarmConfiguration) {
    is JarmConfiguration.Signing -> cfg.holderId
    is JarmConfiguration.Encryption -> cfg.holderId
    is JarmConfiguration.SigningAndEncryption -> cfg.signing.holderId
    JarmConfiguration.NotSupported -> null
}
