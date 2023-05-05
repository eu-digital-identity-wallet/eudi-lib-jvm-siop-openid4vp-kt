package eu.europa.ec.euidw.openid4vp.internal

import eu.europa.ec.euidw.openid4vp.ResolvedRequestData
import eu.europa.ec.euidw.openid4vp.WalletOpenId4VPConfig
import eu.europa.ec.euidw.openid4vp.internal.utils.success

object SiopId4VPRequestResolver  {

   suspend fun resolve(validated: ValidatedSiopId4VPRequestObject, walletOpenId4VPConfig: WalletOpenId4VPConfig): Result<ResolvedRequestData> =
        when (validated) {
            is ValidatedSiopId4VPRequestObject.IdTokenRequestObject -> resolveIdTokenRequest(validated)
            is ValidatedSiopId4VPRequestObject.VpTokenRequestObject -> resolveVpTokenRequest(validated, walletOpenId4VPConfig)
            is ValidatedSiopId4VPRequestObject.IdAndVPTokenRequestObject -> resolveIdAndVpTokenRequest(validated, walletOpenId4VPConfig)
        }

    private suspend fun resolveIdAndVpTokenRequest(validated: ValidatedSiopId4VPRequestObject.IdAndVPTokenRequestObject, walletOpenId4VPConfig: WalletOpenId4VPConfig): Result<ResolvedRequestData> {
        val presentationDefinition =
            PresentationDefinitionResolver.resolve(validated.presentationDefinitionSource, walletOpenId4VPConfig).getOrThrow()
        val clientMetaData = ClientMetaDataResolver.resolve(validated.clientMetaDataSource).getOrThrow()
        return ResolvedRequestData.IdAndVPTokenRequestData(
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

    private suspend fun resolveVpTokenRequest(validated: ValidatedSiopId4VPRequestObject.VpTokenRequestObject, walletOpenId4VPConfig: WalletOpenId4VPConfig): Result<ResolvedRequestData> {
        val presentationDefinition =
            PresentationDefinitionResolver.resolve(validated.presentationDefinitionSource, walletOpenId4VPConfig).getOrThrow()
        val clientMetaData = ClientMetaDataResolver.resolve(validated.clientMetaDataSource).getOrThrow()
        return ResolvedRequestData.VpTokenRequestData(
            presentationDefinition = presentationDefinition,
            clientMetaData = clientMetaData,
            clientId = validated.clientId,
            state = validated.state,
            nonce = validated.nonce,
            responseMode = validated.responseMode
        ).success()
    }

    private suspend fun resolveIdTokenRequest(validated: ValidatedSiopId4VPRequestObject.IdTokenRequestObject): Result<ResolvedRequestData> {
        val clientMetaData = ClientMetaDataResolver.resolve(validated.clientMetaDataSource).getOrThrow()
        return ResolvedRequestData.IdTokenRequestData(
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
