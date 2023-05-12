package eu.europa.ec.euidw.openid4vp.internal.dispatch

import eu.europa.ec.euidw.openid4vp.AuthorizationResponse
import eu.europa.ec.euidw.openid4vp.AuthorizationResponseDispatcher
import eu.europa.ec.euidw.openid4vp.AuthorizationResponsePayload
import eu.europa.ec.euidw.openid4vp.HttpFormPost
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

private const val PRESENTATION_SUBMISSION_FORM_PARAM = "presentation_submission"
private const val VP_TOKEN_FORM_PARAM = "vp_token"
private const val STATE_FORM_PARAM = "state"
private const val ID_TOKEN_FORM_PARAM = "idToken"
private const val ERROR_FORM_PARAM = "error"
private const val ERROR_DESCRIPTION_FORM_PARAM = "error_description"

internal class DirectPostResponseDispatcher(
    val httpFormPost : HttpFormPost
) : AuthorizationResponseDispatcher<AuthorizationResponse.DirectPostResponse, Unit> {

    override suspend fun dispatch(response: AuthorizationResponse.DirectPostResponse)  {
        when (response) {
            is AuthorizationResponse.DirectPostResponse -> dispatch(response)
            is AuthorizationResponse.QueryResponse -> dispatch(response)
        }
    }

    suspend fun dispatch(response : AuthorizationResponse.DirectPost) : Unit {
        val formParameters = response.data.asFormParameters()
        httpFormPost.post(response.responseUri.value, formParameters)
    }

    fun dispatch(response : AuthorizationResponse.DirectPostJwt) : Unit {
        TODO("Not yet implemented")
    }

    private fun AuthorizationResponsePayload.asFormParameters() : Map<String, String> {
        return when (this) {
            is AuthorizationResponsePayload.SiopAuthenticationResponse -> this.asFormParameters()
            is AuthorizationResponsePayload.OpenId4VPAuthorizationResponse -> this.asFormParameters()
            is AuthorizationResponsePayload.SiopOpenId4VPAuthenticationResponse -> this.asFormParameters()
            is AuthorizationResponsePayload.InvalidRequest -> this.asFormParameters()
            is AuthorizationResponsePayload.NoConsensusResponseData -> this.asFormParameters()
        }
    }

    private fun AuthorizationResponsePayload.SiopAuthenticationResponse.asFormParameters() : Map<String, String> =
        mapOf(
            ID_TOKEN_FORM_PARAM to idToken.serialize(),
            STATE_FORM_PARAM to state
        )

    private fun AuthorizationResponsePayload.OpenId4VPAuthorizationResponse.asFormParameters() : Map<String, String> =
        mapOf(
            VP_TOKEN_FORM_PARAM to Json.encodeToString(verifiableCredential),
            PRESENTATION_SUBMISSION_FORM_PARAM to Json.encodeToString(presentationSubmission),
            STATE_FORM_PARAM to state
        )


    private fun AuthorizationResponsePayload.SiopOpenId4VPAuthenticationResponse.asFormParameters() : Map<String, String> =
        mapOf(
            ID_TOKEN_FORM_PARAM to this.idToken.serialize(),
            VP_TOKEN_FORM_PARAM to Json.encodeToString(this.verifiableCredential),
            PRESENTATION_SUBMISSION_FORM_PARAM to Json.encodeToString(this.presentationSubmission),
            STATE_FORM_PARAM to this.state
        )


    private fun AuthorizationResponsePayload.InvalidRequest.asFormParameters() : Map<String, String> {
        val fromError = AuthenticationResponseErrorCode.fromError(error)
        return mapOf(
            ERROR_FORM_PARAM to fromError.code,
            ERROR_DESCRIPTION_FORM_PARAM to "${fromError.description} : $error",
            STATE_FORM_PARAM to this.state
        )
    }

}



