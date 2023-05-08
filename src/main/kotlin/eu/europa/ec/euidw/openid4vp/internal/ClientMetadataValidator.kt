package eu.europa.ec.euidw.openid4vp.internal

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata
import eu.europa.ec.euidw.openid4vp.ClientMetaData
import java.net.URL

object ClientMetadataValidator {

    fun validate(clientMetadata : ClientMetaData) : Result<OIDCClientMetadata> {
        val isValid = hasRequiredJwksSource(clientMetadata) && hasSubjectSyntaxTypes(clientMetadata)
        return when {
            isValid ->  Result.success(valid(clientMetadata))
            else -> Result.failure(IllegalStateException("Client metadata wrong syntax"))
        }
    }

    private fun hasRequiredJwksSource(clientMetadata: ClientMetaData) : Boolean {
        val bothJwksSourcesDefined = !clientMetadata.jwks.isNullOrEmpty() && !clientMetadata.jwksUri.isNullOrEmpty()
        val atLeastOneJwkSourceDefined = !clientMetadata.jwks.isNullOrEmpty() || !clientMetadata.jwksUri.isNullOrEmpty()
        return !bothJwksSourcesDefined && atLeastOneJwkSourceDefined
    }

    private fun hasSubjectSyntaxTypes(clientMetadata: ClientMetaData) : Boolean {
        return !clientMetadata.subjectSyntaxTypesSupported.isEmpty()
    }

    private fun valid(cmtd: ClientMetaData): OIDCClientMetadata {
        val vJwkSet: JWKSet
        if (!cmtd.jwksUri.isNullOrEmpty()) {
            vJwkSet = JWKSet.load(URL(cmtd.jwksUri))
        } else {
            vJwkSet = JWKSet.parse(cmtd.jwks?.toString())
        }
        return OIDCClientMetadata().apply {
            idTokenJWSAlg = JWSAlgorithm.parse(cmtd.idTokenSignedResponseAlg)
            idTokenJWEAlg = JWEAlgorithm.parse(cmtd.idTokenEncryptedResponseAlg)
            idTokenJWEEnc = EncryptionMethod.parse(cmtd.idTokenEncryptedResponseEnc)
            jwkSet = vJwkSet
            setCustomField("subject_syntax_types_supported", cmtd.subjectSyntaxTypesSupported)
        }
    }
}