package eu.europa.ec.euidw.openid4vp

import eu.europa.ec.euidw.openid4vp.internal.DefaultAuthorizationResponseDispatcher

interface AuthorizationResponseDispatcher {

    suspend fun dispatch(response : AuthorizationResponse) : String

    companion object {
        fun make(
            walletOpenId4VPConfig: WalletOpenId4VPConfig,
            httpPost : HttpPost<AuthorizationResponsePayload>,
            httpFormPost : HttpFormPost
        ) : AuthorizationResponseDispatcher {
            return DefaultAuthorizationResponseDispatcher(walletOpenId4VPConfig, httpPost, httpFormPost)
        }


    }

}

