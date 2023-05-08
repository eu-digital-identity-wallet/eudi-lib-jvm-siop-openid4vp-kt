package eu.europa.ec.euidw.openid4vp.internal

import eu.europa.ec.euidw.openid4vp.ResolvedRequestObject
import eu.europa.ec.euidw.openid4vp.WalletOpenId4VPConfig
import eu.europa.ec.euidw.openid4vp.internal.utils.success

internal object ValidatedRequestObjectResolver  {

   suspend fun resolve(validated: ValidatedRequestObject, walletOpenId4VPConfig: WalletOpenId4VPConfig): Result<ResolvedRequestObject> =
        when (validated) {
            is ValidatedRequestObject.IdTokenRequestObject -> resolveIdTokenRequest(validated)
            is ValidatedRequestObject.VpTokenRequestObject -> resolveVpTokenRequest(validated, walletOpenId4VPConfig)
            is ValidatedRequestObject.IdAndVPTokenRequestObject -> resolveIdAndVpTokenRequest(validated, walletOpenId4VPConfig)
        }

    private suspend fun resolveIdAndVpTokenRequest(validated: ValidatedRequestObject.IdAndVPTokenRequestObject, walletOpenId4VPConfig: WalletOpenId4VPConfig): Result<ResolvedRequestObject> {
        val presentationDefinition =
            PresentationDefinitionResolver.resolve(validated.presentationDefinitionSource, walletOpenId4VPConfig).getOrThrow()
        val clientMetaData = ClientMetaDataResolver.resolve(validated.clientMetaDataSource).getOrThrow()
        return ResolvedRequestObject.IdAndVPTokenRequestObject(
            idTokenType = validated.idTokenType,
            presentationDefinition = presentationDefinition,
            clientMetaData = clientMetaData,
            clientId = validated.clientId,
            state = validated.state,
            scope = validated.scope,
            nonce = validated.nonce,
            responseMode = validated.responseMode
        ).success()
    }

    private suspend fun resolveVpTokenRequest(validated: ValidatedRequestObject.VpTokenRequestObject, walletOpenId4VPConfig: WalletOpenId4VPConfig): Result<ResolvedRequestObject> {
        val presentationDefinition =
            PresentationDefinitionResolver.resolve(validated.presentationDefinitionSource, walletOpenId4VPConfig).getOrThrow()
        val clientMetaData = ClientMetaDataResolver.resolve(validated.clientMetaDataSource).getOrThrow()
        return ResolvedRequestObject.VpTokenRequestObject(
            presentationDefinition = presentationDefinition,
            clientMetaData = clientMetaData,
            clientId = validated.clientId,
            state = validated.state,
            nonce = validated.nonce,
            responseMode = validated.responseMode
        ).success()
    }

    private suspend fun resolveIdTokenRequest(validated: ValidatedRequestObject.IdTokenRequestObject): Result<ResolvedRequestObject> {
        val clientMetaData = ClientMetaDataResolver.resolve(validated.clientMetaDataSource).getOrThrow()
        return ResolvedRequestObject.IdTokenRequestObject(
            idTokenType = validated.idTokenType,
            clientMetaData = clientMetaData,
            clientId = validated.clientId,
            state = validated.state,
            scope = validated.scope,
            nonce = validated.nonce,
            responseMode = validated.responseMode
        ).success()
    }
}
