package eu.europa.ec.euidw.openid4vp


interface SiopOpenId4Vp : AuthorizationRequestResolver, AuthorizationResponseBuilder, Dispatcher {


    suspend fun handle(
        uri: String,
        holderConsensus: suspend (ResolvedRequestObject) -> Consensus
    ): DispatchOutcome =
        when (val authorizationRequestResolution = resolveRequestUri(uri)) {
            is Resolution.Invalid -> throw authorizationRequestResolution.error.asException()
            is Resolution.Success -> {
                val requestObject = authorizationRequestResolution.requestObject
                val consensus = holderConsensus(requestObject)
                val authorizationResponse = build(requestObject, consensus)
                dispatch(authorizationResponse)
            }
        }


    companion object {
        fun ktor(
            walletOpenId4VPConfig: WalletOpenId4VPConfig,
            httpClientFactory: KtorHttpClientFactory = SiopOpenId4VpKtor.DefaultFactory
        ): SiopOpenId4Vp = SiopOpenId4VpKtor(walletOpenId4VPConfig, httpClientFactory)

    }
}