package eu.europa.ec.euidw.openid4vp

import eu.europa.ec.euidw.openid4vp.internal.ktor.HttpKtorAdapter
import eu.europa.ec.euidw.openid4vp.internal.ktor.KtorAuthorizationRequestResolver
import eu.europa.ec.euidw.openid4vp.internal.ktor.KtorDispatcher
import io.ktor.client.*

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
            httpClientFactory: () -> HttpClient = { HttpKtorAdapter.createKtorClient() }
        ): SiopOpenId4Vp = object : SiopOpenId4Vp {

            private val dispatcher: Dispatcher by lazy { ktorDispatcher(httpClientFactory) }
            private val resolver: AuthorizationRequestResolver by lazy {
                ktorResolver(
                    walletOpenId4VPConfig,
                    httpClientFactory
                )
            }
            private val responseBuilder: AuthorizationResponseBuilder by lazy { AuthorizationResponseBuilder.Default }

            override suspend fun resolveRequest(request: AuthorizationRequest): Resolution =
                resolver.resolveRequest(request)

            override suspend fun build(
                requestObject: ResolvedRequestObject,
                consensus: Consensus
            ): AuthorizationResponse = responseBuilder.build(requestObject, consensus)

            override suspend fun dispatch(response: AuthorizationResponse): DispatchOutcome =
                dispatcher.dispatch(response)
        }


        /**
         * A factory method for obtaining an instance of [AuthorizationRequestResolver] which
         * uses the Ktor client for performing http calls
         */
        private fun ktorResolver(
            walletOpenId4VPConfig: WalletOpenId4VPConfig,
            httpClientFactory: () -> HttpClient = { HttpKtorAdapter.createKtorClient() }
        ): AuthorizationRequestResolver = AuthorizationRequestResolver { request ->
            KtorAuthorizationRequestResolver(
                walletOpenId4VPConfig,
                httpClientFactory
            ).use { it.resolveRequest(request) }
        }

        private fun ktorDispatcher(httpClientFactory: () -> HttpClient = { HttpKtorAdapter.createKtorClient() }): Dispatcher =
            KtorDispatcher(httpClientFactory)
    }
}