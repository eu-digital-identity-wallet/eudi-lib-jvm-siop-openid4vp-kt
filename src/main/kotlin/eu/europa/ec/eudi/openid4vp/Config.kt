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

import eu.europa.ec.eudi.prex.ClaimFormat
import eu.europa.ec.eudi.prex.PresentationDefinition
import eu.europa.ec.eudi.prex.SupportedClaimFormat
import java.time.Duration

sealed interface SupportedClientIdScheme {
    val scheme: ClientIdScheme
        get() = when (this) {
            is Preregistered -> ClientIdScheme.PreRegistered
            is RedirectUri -> ClientIdScheme.RedirectUri
            is IsoX509 -> ClientIdScheme.ISO_X509
        }
    val preregisteredClients: List<ClientMetaData>
        get() = when (this) {
            is Preregistered -> clients
            is RedirectUri -> emptyList()
            is IsoX509 -> emptyList()
        }

    fun isClientIdSupported(clientIdScheme: ClientIdScheme): Boolean = clientIdScheme == scheme

    data class Preregistered(val clients: List<ClientMetaData>) : SupportedClientIdScheme
    object RedirectUri : SupportedClientIdScheme
    object IsoX509 : SupportedClientIdScheme
}

data class WalletOpenId4VPConfig(
    val subjectSyntaxTypesSupported: List<SubjectSyntaxType>,
    val preferredSubjectSyntaxType: SubjectSyntaxType = SubjectSyntaxType.JWKThumbprint,
    val decentralizedIdentifier: String = "DID:example:12341512#$",
    val idTokenTTL: Duration = Duration.ofMinutes(10),
    val presentationDefinitionUriSupported: Boolean = false,
    val supportedClientIdScheme: SupportedClientIdScheme,
    val vpFormatsSupported: List<SupportedClaimFormat<in ClaimFormat>>,
    val knownPresentationDefinitionsPerScope: Map<String, PresentationDefinition> = emptyMap(),
)
