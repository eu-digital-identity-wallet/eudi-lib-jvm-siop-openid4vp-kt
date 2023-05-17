package eu.europa.ec.euidw.openid4vp

import eu.europa.ec.euidw.prex.ClaimFormat
import eu.europa.ec.euidw.prex.PresentationDefinition
import eu.europa.ec.euidw.prex.SupportedClaimFormat
import kotlinx.serialization.SerialName
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

data class VPFormatsFormatsSupported(val formats: List<SupportedClaimFormat<*>>)
data class WalletOpenId4VPMetaData(
    /**
     * OPTIONAL. Boolean value specifying whether the Wallet supports
     * the transfer of presentation_definition by reference,
     * with true indicating support. If omitted, the default value is true.
     */
    @SerialName("presentation_definition_uri_supported") val presentationDefinitionUriSupported: Boolean = true,
    @SerialName("vp_formats_supported") val vpFormatsSupported: VPFormatsFormatsSupported,
    @SerialName("client_id_schemes_supported") val clientIdSchemesSupported: List<ClientIdScheme>

)

data class WalletOpenId4VPConfig(
    val subjectSyntaxTypesSupported: List<SubjectSyntaxType>,
    val preferredSubjectSyntaxType: SubjectSyntaxType = SubjectSyntaxType.JWKThumbprint,
    val decentralizedIdentifier: String = "DID:example:12341512#$",
    val idTokenTTL: Duration = Duration.ofMinutes(10),
    val presentationDefinitionUriSupported: Boolean = false,
    val supportedClientIdScheme: SupportedClientIdScheme,
    val vpFormatsSupported: List<SupportedClaimFormat<in ClaimFormat>>,
    val knownPresentationDefinitionsPerScope: Map<String, PresentationDefinition> = emptyMap()
) {

//    init {
//        require(vpFormatsSupported.isNotEmpty())
//    }

}