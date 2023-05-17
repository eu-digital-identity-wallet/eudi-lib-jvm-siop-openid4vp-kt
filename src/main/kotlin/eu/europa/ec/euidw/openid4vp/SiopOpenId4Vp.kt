package eu.europa.ec.euidw.openid4vp

import eu.europa.ec.euidw.openid4vp.internal.ktor.HttpKtorAdapter
import eu.europa.ec.euidw.openid4vp.internal.ktor.KtorAuthorizationRequestResolver
import eu.europa.ec.euidw.openid4vp.internal.ktor.KtorDispatcher
import io.ktor.client.*

interface SiopOpenId4Vp {

    val resolver: AuthorizationRequestResolver
    val responseBuilder: AuthorizationResponseBuilder
    val dispatcher: Dispatcher

    suspend fun handle(
        uri: String,
        holderConsensus: suspend (ResolvedRequestObject) -> Consensus
    ): DispatchOutcome =
        when (val authorizationRequestResolution = resolver.resolveRequestUri(uri)) {
            is Resolution.Invalid -> throw authorizationRequestResolution.error.asException()
            is Resolution.Success -> {
                val requestObject = authorizationRequestResolution.requestObject
                val consensus = holderConsensus(requestObject)
                val authorizationResponse = responseBuilder.build(requestObject, consensus)
                dispatcher.dispatch(authorizationResponse)
            }
        }


    companion object {
        fun ktor(
            walletOpenId4VPConfig: WalletOpenId4VPConfig,
            httpClientFactory: () -> HttpClient = { HttpKtorAdapter.createKtorClient() }
        ): SiopOpenId4Vp = object : SiopOpenId4Vp {
            override val dispatcher: Dispatcher = ktorDispatcher(httpClientFactory)
            override val resolver: AuthorizationRequestResolver = ktorResolver(walletOpenId4VPConfig, httpClientFactory)
            override val responseBuilder: AuthorizationResponseBuilder = AuthorizationResponseBuilder.Default
        }


        /**
         * A factory method for obtaining an instance of [AuthorizationRequestResolver] which
         * uses the Ktor client for performing http calls
         */
        fun ktorResolver(
            walletOpenId4VPConfig: WalletOpenId4VPConfig,
            httpClientFactory: () -> HttpClient = { HttpKtorAdapter.createKtorClient() }
        ): AuthorizationRequestResolver = AuthorizationRequestResolver { request ->
            KtorAuthorizationRequestResolver(
                walletOpenId4VPConfig,
                httpClientFactory
            ).use { it.resolveRequest(request) }
        }

        fun ktorDispatcher(httpClientFactory: () -> HttpClient = { HttpKtorAdapter.createKtorClient() }): Dispatcher =
            KtorDispatcher(httpClientFactory)
    }
}