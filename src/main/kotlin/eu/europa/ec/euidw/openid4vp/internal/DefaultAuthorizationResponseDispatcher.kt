package eu.europa.ec.euidw.openid4vp.internal

import eu.europa.ec.euidw.openid4vp.*
import eu.europa.ec.euidw.openid4vp.internal.dispatch.DirectPostResponseDispatcher

internal class DefaultAuthorizationResponseDispatcher(
    private val walletOpenId4VPConfig: WalletOpenId4VPConfig,
    private val httpPost : HttpPost<AuthorizationResponsePayload>,
    private val httpFormPost : HttpFormPost,
) : AuthorizationResponseDispatcher {

    private val directPostDispatcher = DirectPostResponseDispatcher(httpFormPost)
    override suspend fun dispatch(response: AuthorizationResponse) : String =
        when (response) {
            is AuthorizationResponse.DirectPostResponse -> handleDirectPost(response)
            is AuthorizationResponse.FragmentResponse -> handleFragment(response)
            is AuthorizationResponse.QueryResponse -> handleQuery(response)
        }

    private suspend fun handleDirectPost(response: AuthorizationResponse.DirectPostResponse): String =
        when (response) {
            is AuthorizationResponse.DirectPost -> directPostDispatcher.dispatch(response)
            is AuthorizationResponse.DirectPostJwt -> directPostDispatcher.dispatch(response)
        }


    private suspend fun handleQuery(response: AuthorizationResponse.QueryResponse): String =
        when (response) {
            is AuthorizationResponse.Query -> TODO()
            is AuthorizationResponse.QueryJwt -> TODO()
        }


    private suspend fun handleFragment(response: AuthorizationResponse.FragmentResponse): String =
        when (response) {
            is AuthorizationResponse.Fragment -> TODO()
            is AuthorizationResponse.FragmentJwt -> TODO()
        }


}