package eu.europa.ec.eudi.openid4vp.internal.dispatch

import com.eygraber.uri.UriCodec
import com.eygraber.uri.toURI
import com.eygraber.uri.toUri
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.prex.PresentationSubmission
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/**
 * Default implementation of [Dispatcher]
 *
 * @param ioCoroutineDispatcher the coroutine dispatcher to handle IO
 * @param httpFormPost the abstraction to an HTTP post operation
 */
internal class DefaultDispatcher(
    private val ioCoroutineDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val httpFormPost: HttpFormPost<DispatchOutcome.VerifierResponse>,
) : Dispatcher {
    override suspend fun dispatch(response: AuthorizationResponse): DispatchOutcome =
        when (response) {
            is AuthorizationResponse.DirectPost -> directPost(response)
            is AuthorizationResponse.DirectPostJwt -> directPostJwt(response)
            is AuthorizationResponse.RedirectResponse -> redirectURI(response)
        }

    /**
     * Implements the direct_post method by performing a form-encoded HTTP post
     * @param response the response to be communicated via direct_post
     * @return the [response][DispatchOutcome.VerifierResponse] fo the verifier
     * @see DirectPostForm on how the given [response] is encoded into form data
     */
    private suspend fun directPost(response: AuthorizationResponse.DirectPost): DispatchOutcome.VerifierResponse =
        withContext(ioCoroutineDispatcher) {
            val formParameters = DirectPostForm.of(response.data)
            httpFormPost.post(response.responseUri, formParameters)
        }

    private suspend fun directPostJwt(response: AuthorizationResponse.DirectPostJwt): DispatchOutcome.VerifierResponse =
        withContext(ioCoroutineDispatcher) {
            error("Not yet implemented directPostJwt")
        }

    private fun redirectURI(response: AuthorizationResponse.RedirectResponse): DispatchOutcome.RedirectURI =
        with(response.redirectUri.toUri().buildUpon()) {
            when (response) {
                is AuthorizationResponse.Fragment -> {
                    val encodedFragment = DirectPostForm.of(response.data).map { (key, value) ->
                        val encodedKey = UriCodec.encode(key, null)
                        val encodedValue = UriCodec.encodeOrNull(value, null)
                        "$encodedKey=$encodedValue"
                    }.joinToString(separator = "&")
                    encodedFragment(encodedFragment)
                }

                is AuthorizationResponse.Query ->
                    DirectPostForm.of(response.data).forEach { (key, value) -> appendQueryParameter(key, value) }

                is AuthorizationResponse.FragmentJwt -> error("Not yet implemented")
                is AuthorizationResponse.QueryJwt -> error("Not yet implemented")
            }
            return DispatchOutcome.RedirectURI(build().toURI())
        }
}

/**
 * An object responsible for encoding a [AuthorizationResponsePayload] into
 * HTTP form
 */
private object DirectPostForm {

    private const val PRESENTATION_SUBMISSION_FORM_PARAM = "presentation_submission"
    private const val VP_TOKEN_FORM_PARAM = "vp_token"
    private const val STATE_FORM_PARAM = "state"
    private const val ID_TOKEN_FORM_PARAM = "id_token"
    private const val ERROR_FORM_PARAM = "error"
    private const val ERROR_DESCRIPTION_FORM_PARAM = "error_description"

    fun of(p: AuthorizationResponsePayload): Map<String, String> {
        fun ps(ps: PresentationSubmission) = Json.encodeToString<PresentationSubmission>(ps)
        fun vpToken(vcs: List<Jwt>) = Json.encodeToString<List<Jwt>>(vcs)
        return when (p) {
            is AuthorizationResponsePayload.SiopAuthenticationResponse -> mapOf(
                ID_TOKEN_FORM_PARAM to p.idToken,
                STATE_FORM_PARAM to p.state,
            )

            is AuthorizationResponsePayload.OpenId4VPAuthorizationResponse -> mapOf(
                VP_TOKEN_FORM_PARAM to vpToken(p.verifiableCredential),
                PRESENTATION_SUBMISSION_FORM_PARAM to ps(p.presentationSubmission),
                STATE_FORM_PARAM to p.state,
            )

            is AuthorizationResponsePayload.SiopOpenId4VPAuthenticationResponse -> mapOf(
                ID_TOKEN_FORM_PARAM to p.idToken,
                VP_TOKEN_FORM_PARAM to vpToken(p.verifiableCredential),
                PRESENTATION_SUBMISSION_FORM_PARAM to ps(p.presentationSubmission),
                STATE_FORM_PARAM to p.state,
            )

            is AuthorizationResponsePayload.InvalidRequest -> mapOf(
                ERROR_FORM_PARAM to AuthorizationRequestErrorCode.fromError(p.error).code,
                ERROR_DESCRIPTION_FORM_PARAM to "${p.error}",
                STATE_FORM_PARAM to p.state,
            )

            is AuthorizationResponsePayload.NoConsensusResponseData -> mapOf(
                ERROR_FORM_PARAM to AuthorizationRequestErrorCode.USER_CANCELLED.code,
                STATE_FORM_PARAM to p.state,
            )
        }
    }
}
