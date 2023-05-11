package eu.europa.ec.euidw.openid4vp

import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import eu.europa.ec.euidw.prex.ClaimFormat
import kotlinx.serialization.SerialName
import eu.europa.ec.euidw.prex.PresentationDefinition
import eu.europa.ec.euidw.prex.SupportedClaimFormat
import java.time.Duration
import java.util.*


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
    val client_id_schemes_supported: List<ClientIdScheme>

)

data class WalletOpenId4VPConfig(
    val subjectSyntaxTypesSupported : List<SubjectSyntaxType>,
    val preferredSubjectSyntaxType : SubjectSyntaxType = SubjectSyntaxType.JWKThumbprint,
    val decentralizedIdentifier : String = "DID:example:12341512#$",
    val idTokenTTL : Duration = Duration.ofMinutes(10),
    val presentationDefinitionUriSupported: Boolean = false,
    val supportedClientIdScheme: SupportedClientIdScheme,
    val vpFormatsSupported : List<SupportedClaimFormat<in ClaimFormat>>,
    val knownPresentationDefinitionsPerScope: Map<String, PresentationDefinition> = emptyMap(),
    val holderEmail : String = "example@euidw.com",
    val holderName : String = "Holder Name",
    val rsaJWK: RSAKey = RSAKeyGenerator(2048)
        .keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key (optional)
        .keyID(UUID.randomUUID().toString()) // give the key a unique ID (optional)
        .issueTime(Date(System.currentTimeMillis())) // issued-at timestamp (optional)
        .generate()
) {

//    init {
//        require(vpFormatsSupported.isNotEmpty())
//    }

}