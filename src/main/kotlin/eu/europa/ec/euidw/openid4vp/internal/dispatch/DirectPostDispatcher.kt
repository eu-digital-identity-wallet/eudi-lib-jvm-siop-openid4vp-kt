package eu.europa.ec.euidw.openid4vp.internal.dispatch

import eu.europa.ec.euidw.openid4vp.AuthorizationResponse.DirectPost
import eu.europa.ec.euidw.openid4vp.AuthorizationResponse.DirectPostJwt

import eu.europa.ec.euidw.openid4vp.AuthorizationResponsePayload
import eu.europa.ec.euidw.openid4vp.AuthorizationResponsePayload.*
import eu.europa.ec.euidw.openid4vp.HttpFormPost
import eu.europa.ec.euidw.openid4vp.Jwt
import eu.europa.ec.euidw.openid4vp.internal.dispatch.AuthenticationResponseErrorCode.Companion.fromError
import eu.europa.ec.euidw.prex.PresentationSubmission
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json


internal class DirectPostDispatcher(
    private val httpFormPost: HttpFormPost<Unit>
) : AuthorizationResponseDispatcher<DirectPost, Unit> {

    override suspend fun dispatch(response: DirectPost) = withContext(Dispatchers.IO) {
        val formParameters = Form.from(response.data)
        httpFormPost.post(response.responseUri.value, formParameters)
    }
}

internal class DirectPostJwtDispatcher(
    private val httpFormPost: HttpFormPost<Unit>
) : AuthorizationResponseDispatcher<DirectPostJwt, Unit> {

    override suspend fun dispatch(response: DirectPostJwt) = withContext(Dispatchers.IO) {
        TODO("Not yet implemented")
    }
}

private object Form {

    private const val PRESENTATION_SUBMISSION_FORM_PARAM = "presentation_submission"
    private const val VP_TOKEN_FORM_PARAM = "vp_token"
    private const val STATE_FORM_PARAM = "state"
    private const val ID_TOKEN_FORM_PARAM = "idToken"
    private const val ERROR_FORM_PARAM = "error"
    private const val ERROR_DESCRIPTION_FORM_PARAM = "error_description"

    fun from(p: AuthorizationResponsePayload): Map<String, String> = when (p) {
        is SiopAuthenticationResponse -> mapOf(
            ID_TOKEN_FORM_PARAM to p.idToken,
            STATE_FORM_PARAM to p.state
        )

        is OpenId4VPAuthorizationResponse -> mapOf(
            VP_TOKEN_FORM_PARAM to Json.encodeToString<List<Jwt>>(p.verifiableCredential),
            PRESENTATION_SUBMISSION_FORM_PARAM to Json.encodeToString<PresentationSubmission>(
                p.presentationSubmission
            ),
            STATE_FORM_PARAM to p.state
        )

        is SiopOpenId4VPAuthenticationResponse -> mapOf(
            ID_TOKEN_FORM_PARAM to p.idToken,
            VP_TOKEN_FORM_PARAM to Json.encodeToString<List<Jwt>>(p.verifiableCredential),
            PRESENTATION_SUBMISSION_FORM_PARAM to Json.encodeToString<PresentationSubmission>(
                p.presentationSubmission
            ),
            STATE_FORM_PARAM to p.state
        )

        is InvalidRequest -> {
            val (erroCode, description) = fromError(p.error)
            mapOf(
                ERROR_FORM_PARAM to erroCode,
                ERROR_DESCRIPTION_FORM_PARAM to "$description : ${p.error}",
                STATE_FORM_PARAM to p.state
            )
        }

        is NoConsensusResponseData -> TODO()
    }
}



