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
) {

//    init {
//        require(vpFormatsSupported.isNotEmpty())
//    }
}
