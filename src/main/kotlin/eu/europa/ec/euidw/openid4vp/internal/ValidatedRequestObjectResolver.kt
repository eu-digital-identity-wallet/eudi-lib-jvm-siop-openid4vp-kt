package eu.europa.ec.euidw.openid4vp.internal

import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata
import eu.europa.ec.euidw.openid4vp.PresentationDefinitionSource
import eu.europa.ec.euidw.openid4vp.ResolvedRequestObject
import eu.europa.ec.euidw.openid4vp.WalletOpenId4VPConfig
import eu.europa.ec.euidw.openid4vp.internal.ValidatedRequestObject.*
import eu.europa.ec.euidw.prex.PresentationDefinition

internal class ValidatedRequestObjectResolver(
    private val presentationDefinitionResolver: PresentationDefinitionResolver,
    private val clientMetaDataResolver: ClientMetaDataResolver,
    ) {

    suspend fun resolve(
        validated: ValidatedRequestObject,
        walletOpenId4VPConfig: WalletOpenId4VPConfig
    ): Result<ResolvedRequestObject> = when (validated) {
        is IdTokenRequestObject -> resolveIdTokenRequest(validated)
        is VpTokenRequestObject -> resolveVpTokenRequest(validated, walletOpenId4VPConfig)
        is IdAndVPTokenRequestObject -> resolveIdAndVpTokenRequest(validated, walletOpenId4VPConfig)
    }

    private suspend fun resolveIdAndVpTokenRequest(
        validated: IdAndVPTokenRequestObject,
        walletOpenId4VPConfig: WalletOpenId4VPConfig
    ): Result<ResolvedRequestObject> {
        val presentationDefinition =
            resolvePd(validated.presentationDefinitionSource, walletOpenId4VPConfig).getOrThrow()
        return ResolvedRequestObject.IdAndVPTokenRequestObject(
            idTokenType = validated.idTokenType,
            presentationDefinition = presentationDefinition,
            clientMetaData = resolveClientMetaData(validated).getOrThrow(),
            clientId = validated.clientId,
            state = validated.state,
            scope = validated.scope,
            nonce = validated.nonce,
            responseMode = validated.responseMode
        ).success()
    }

    private suspend fun resolveVpTokenRequest(
        validated: VpTokenRequestObject,
        walletOpenId4VPConfig: WalletOpenId4VPConfig
    ): Result<ResolvedRequestObject> {
        val presentationDefinition =
            resolvePd(validated.presentationDefinitionSource, walletOpenId4VPConfig)
                .getOrThrow()
        return ResolvedRequestObject.VpTokenRequestObject(
            presentationDefinition = presentationDefinition,
            clientMetaData = resolveClientMetaData(validated).getOrThrow(),
            clientId = validated.clientId,
            state = validated.state,
            nonce = validated.nonce,
            responseMode = validated.responseMode
        ).success()
    }

    private suspend fun resolveIdTokenRequest(validated: IdTokenRequestObject): Result<ResolvedRequestObject> =
        ResolvedRequestObject.IdTokenRequestObject(
            idTokenType = validated.idTokenType,
            clientMetaData = resolveClientMetaData(validated).getOrThrow(),
            clientId = validated.clientId,
            state = validated.state,
            scope = validated.scope,
            nonce = validated.nonce,
            responseMode = validated.responseMode
        ).success()


    private suspend fun resolvePd(
        presentationDefinitionSource: PresentationDefinitionSource,
        walletOpenId4VPConfig: WalletOpenId4VPConfig
    ): Result<PresentationDefinition> {
        return presentationDefinitionResolver.resolve(presentationDefinitionSource, walletOpenId4VPConfig)
    }

    private suspend fun resolveClientMetaData(validated: ValidatedRequestObject): Result<OIDCClientMetadata> {
        return validated.clientMetaDataSource?.let {
            clientMetaDataResolver.resolve(it)
        } ?: throw IllegalArgumentException("Missing client metadata")


    }
}
