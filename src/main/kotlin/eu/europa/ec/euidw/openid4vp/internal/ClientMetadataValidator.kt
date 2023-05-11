package eu.europa.ec.euidw.openid4vp.internal

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata
import eu.europa.ec.euidw.openid4vp.ClientMetaData
import kotlinx.coroutines.Dispatchers
import java.net.URL

object ClientMetadataValidator {

    suspend fun  validate(clientMetadata: ClientMetaData): Result<OIDCClientMetadata> {
        val isValid = hasRequiredJwksSource(clientMetadata) && hasSubjectSyntaxTypes(clientMetadata)
        return when {
            isValid -> Result.success(valid(clientMetadata))
            else -> Result.failure(IllegalStateException("Client metadata wrong syntax"))
        }
    }

    private fun hasRequiredJwksSource(clientMetadata: ClientMetaData): Boolean {
        val bothJwksSourcesDefined = !clientMetadata.jwks.isNullOrEmpty() && !clientMetadata.jwksUri.isNullOrEmpty()
        val atLeastOneJwkSourceDefined = !clientMetadata.jwks.isNullOrEmpty() || !clientMetadata.jwksUri.isNullOrEmpty()
        return !bothJwksSourcesDefined && atLeastOneJwkSourceDefined
    }

    private fun hasSubjectSyntaxTypes(clientMetadata: ClientMetaData) =
        clientMetadata.subjectSyntaxTypesSupported.isNotEmpty()

    private suspend fun valid(clientMetaData: ClientMetaData): OIDCClientMetadata {

        val vJwkSet = when {
            clientMetaData.jwksUri.isNullOrEmpty() -> JWKSet.parse(clientMetaData.jwks?.toString())
            else -> {
                // TODO this should be launched in coroutine, since it is blocking
                JWKSet.load(URL(clientMetaData.jwksUri))
            }
        }

        return OIDCClientMetadata().apply {
            idTokenJWSAlg = JWSAlgorithm.parse(clientMetaData.idTokenSignedResponseAlg)
            idTokenJWEAlg = JWEAlgorithm.parse(clientMetaData.idTokenEncryptedResponseAlg)
            idTokenJWEEnc = EncryptionMethod.parse(clientMetaData.idTokenEncryptedResponseEnc)
            jwkSet = vJwkSet
            setCustomField("subject_syntax_types_supported", clientMetaData.subjectSyntaxTypesSupported)
        }
    }
}