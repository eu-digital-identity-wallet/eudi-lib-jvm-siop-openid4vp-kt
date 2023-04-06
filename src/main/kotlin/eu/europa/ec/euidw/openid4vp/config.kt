package eu.europa.ec.euidw.openid4vp

import kotlinx.serialization.SerialName
import eu.europa.ec.euidw.prex.PresentationDefinition
import eu.europa.ec.euidw.prex.SupportedClaimFormat



sealed interface SupportedClientIdScheme {
    val scheme: ClientIdScheme
        get() = when (this) {
            is Preregistered -> ClientIdScheme.PreRegistered
            is RedirectUri -> ClientIdScheme.RedirectUri
        }
    val preregisteredClients: List<ClientMetaData>
        get() = when (this) {
            is Preregistered -> clients
            is RedirectUri -> emptyList()
        }

    fun isClientIdSupported(clientIdScheme: ClientIdScheme): Boolean = clientIdScheme == scheme

    data class Preregistered(val clients: List<ClientMetaData>) : SupportedClientIdScheme
    object RedirectUri : SupportedClientIdScheme

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
    val client_id_schemes_supported: List<ClientIdScheme>

)

data class WalletOpenId4VPConfig(
    val presentationDefinitionUriSupported: Boolean = false,
    val supportedClientIdScheme: SupportedClientIdScheme,
    val vpFormatsSupported : List<SupportedClaimFormat<*>>,
    val knownPresentationDefinitionsPerScope: Map<String, PresentationDefinition> = emptyMap()

) {

    init {
        require(vpFormatsSupported.isNotEmpty())
    }

}