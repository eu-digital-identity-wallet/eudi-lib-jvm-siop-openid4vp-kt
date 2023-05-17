package eu.europa.ec.euidw.openid4vp


/**
 * An interface providing support for handling
 * an OAUTH2 authorization request that represents
 * either an SIOP authentication request, or a OpenId4VP authorization request or
 * a combined SIOP & OpenId4VP request
 *
 * The support is grouped into three groups:
 * [validate & resolve][AuthorizationRequestResolver]
 * [build response][AuthorizationResponseBuilder]
 * [dispatch response][Dispatcher]
 *
 * @see AuthorizationRequestResolver
 * @see AuthorizationResponseBuilder
 * @see Dispatcher
 */
interface SiopOpenId4Vp : AuthorizationRequestResolver, AuthorizationResponseBuilder, Dispatcher {


    /**
     *
     */
    suspend fun handle(
        uri: String,
        holderConsensus: suspend (ResolvedRequestObject) -> Consensus
    ): DispatchOutcome =
        when (val resolution = resolveRequestUri(uri)) {
            is Resolution.Invalid -> throw resolution.error.asException()
            is Resolution.Success -> {
                val requestObject = resolution.requestObject
                val consensus = holderConsensus(requestObject)
                val authorizationResponse = build(requestObject, consensus)
                dispatch(authorizationResponse)
            }
        }


    companion object {

        /**
         * Factory method to create a [SiopOpenId4Vp] based
         * on ktor
         *
         * @param walletOpenId4VPConfig wallet's configuration
         * @param httpClientFactory a factory to obtain Ktor http client
         * @return a [SiopOpenId4Vp]
         *
         * @see SiopOpenId4VpKtor
         */
        fun ktor(
            walletOpenId4VPConfig: WalletOpenId4VPConfig,
            httpClientFactory: KtorHttpClientFactory = SiopOpenId4VpKtor.DefaultFactory
        ): SiopOpenId4Vp = SiopOpenId4VpKtor(walletOpenId4VPConfig, httpClientFactory)

    }
}