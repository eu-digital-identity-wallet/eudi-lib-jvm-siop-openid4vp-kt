package eu.europa.ec.euidw.openid4vp

object SiopOpenId4Vp {

    suspend fun resolveRequestUri(walletOpenId4VPConfig: WalletOpenId4VPConfig, uri: String): Resolution =
        ManagedAuthorizationRequestResolver.ktor(walletOpenId4VPConfig).use { resolver ->
            resolver.resolveRequestUri(uri)
        }


    suspend fun buildAuthorizationResponse(
        requestObject: ResolvedRequestObject,
        consensus: Consensus
    ): AuthorizationResponse =
        AuthorizationResponseBuilder.Default.build(requestObject, consensus)

    suspend fun dispatchAuthorizationResponse(response: AuthorizationResponse): DispatchOutcome =
        Dispatcher.Default.dispatch(response)


    suspend fun handle(
        walletOpenId4VPConfig: WalletOpenId4VPConfig,
        uri: String,
        holderConsensus: suspend (ResolvedRequestObject) -> Consensus
    ): DispatchOutcome =
        when (val authorizationRequestResolution = resolveRequestUri(walletOpenId4VPConfig, uri)) {
            is Resolution.Invalid -> TODO("Implement handle of Invalid Resolution")
            is Resolution.Success -> {
                val requestObject = authorizationRequestResolution.requestObject
                val consensus = holderConsensus(requestObject)
                val authorizationResponse = buildAuthorizationResponse(requestObject, consensus)
                dispatchAuthorizationResponse(authorizationResponse)
            }
        }
}