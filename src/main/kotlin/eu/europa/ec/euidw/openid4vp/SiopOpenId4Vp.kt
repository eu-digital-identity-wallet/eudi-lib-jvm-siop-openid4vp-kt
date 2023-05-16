package eu.europa.ec.euidw.openid4vp

object SiopOpenId4Vp {

    @JvmStatic
    suspend fun resolveRequestUri(walletOpenId4VPConfig: WalletOpenId4VPConfig, uri: String): Resolution =
        resolver(walletOpenId4VPConfig).use { resolver -> resolver.resolveRequestUri(uri) }
    @JvmStatic
    suspend fun resolveRequest(
        walletOpenId4VPConfig: WalletOpenId4VPConfig,
        authorizationRequest: AuthorizationRequest
    ): Resolution =
        resolver(walletOpenId4VPConfig).use { resolver -> resolver.resolveRequest(authorizationRequest) }

    @JvmStatic
    suspend fun buildAuthorizationResponse(
        requestObject: ResolvedRequestObject,
        consensus: Consensus
    ): AuthorizationResponse =
        AuthorizationResponseBuilder.Default.build(requestObject, consensus)

    @JvmStatic
    suspend fun dispatchAuthorizationResponse(response: AuthorizationResponse): DispatchOutcome =
        Dispatcher.Default.dispatch(response)


    @JvmStatic
    suspend fun handle(
        walletOpenId4VPConfig: WalletOpenId4VPConfig,
        uri: String,
        holderConsensus: suspend (ResolvedRequestObject) -> Consensus
    ): DispatchOutcome =
        when (val authorizationRequestResolution = resolveRequestUri(walletOpenId4VPConfig, uri)) {
            is Resolution.Invalid -> throw authorizationRequestResolution.error.asException()
            is Resolution.Success -> {
                val requestObject = authorizationRequestResolution.requestObject
                val consensus = holderConsensus(requestObject)
                val authorizationResponse = buildAuthorizationResponse(requestObject, consensus)
                dispatchAuthorizationResponse(authorizationResponse)
            }
        }

    @JvmStatic
    private fun resolver(walletOpenId4VPConfig: WalletOpenId4VPConfig): ManagedAuthorizationRequestResolver =
        ManagedAuthorizationRequestResolver.ktor(walletOpenId4VPConfig)
}