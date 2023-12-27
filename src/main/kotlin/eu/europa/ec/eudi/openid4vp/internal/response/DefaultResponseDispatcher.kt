/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.openid4vp.internal.response

import com.eygraber.uri.UriCodec
import com.eygraber.uri.toURI
import com.eygraber.uri.toUri
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.internal.response.AuthorizationResponse.*
import eu.europa.ec.eudi.prex.PresentationSubmission
import io.ktor.client.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.net.URI
import java.net.URL

/**
 * Default implementation of [Dispatcher]
 *
 * @param httpClientFactory factory to obtain [HttpClient]
 */
internal class DefaultDispatcher(
    private val httpClientFactory: KtorHttpClientFactory,
    private val holderId: String?,
    private val signer: AuthorizationResponseSigner?,
) : Dispatcher {

    override suspend fun post(request: ResolvedRequestObject, consensus: Consensus): DispatchOutcome.VerifierResponse =
        when (val response = request.responseWith(consensus)) {
            is DirectPost -> directPost(response)
            is DirectPostJwt -> directPostJwt(response)
            else -> error("Unexpected response $response")
        }

    /**
     * Implements the direct_post method by performing a form-encoded HTTP post
     * @param response the response to be communicated via direct_post
     * @return the [response][DispatchOutcome.VerifierResponse] from the verifier
     * @see DirectPostForm on how the given [response] is encoded into form data
     */
    private suspend fun directPost(response: DirectPost): DispatchOutcome.VerifierResponse =
        coroutineScope {
            val parameters = DirectPostForm.of(response.data)
                .let { form ->
                    Parameters.build {
                        form.entries.forEach { append(it.key, it.value) }
                    }
                }

            val verifierResponse = submitForm(response.responseUri, parameters)
            when (verifierResponse.status) {
                HttpStatusCode.OK -> DispatchOutcome.VerifierResponse.Accepted(null)
                else -> DispatchOutcome.VerifierResponse.Rejected
            }
        }

    /**
     * Submits an HTTP Form to [url] with the provided [parameters].
     */
    private suspend fun submitForm(url: URL, parameters: Parameters): HttpResponse =
        httpClientFactory().use { client ->
            client.submitForm(url.toExternalForm(), parameters)
        }

    /**
     * Implements the direct_post.jwt method by performing a form-encoded HTTP post.
     * The posted form's payload is:
     * <ul>
     *     <li>'response' form param: Response data signed and/or encrypted as per [JARM][https://openid.net/specs/openid-financial-api-jarm.html] spec.</li>
     *     <li>'sate' form param: The state attribute as specified in authorization request</li>
     * </ul>
     * @param response the response to be communicated via direct_post.jwt
     * @return the [response][DispatchOutcome.VerifierResponse] from the verifier
     * **See Also:** [JARM](https://openid.net/specs/openid-financial-api-jarm.html) specification for details regarding
     * response signing/encryption
     * **See Also:** [OpenId4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-signed-and-encrypted-respon)
     * for details about direct_post.jwt response type
     */
    private suspend fun directPostJwt(
        response: DirectPostJwt,
    ): DispatchOutcome.VerifierResponse =
        coroutineScope {
            val joseResponse = signEncryptResponse(
                holderId = checkNotNull(holderId),
                signer = signer,
                jarmOption = response.jarmOption,
                data = response.data,
            )
            val parameters = Parameters.build {
                append("response", joseResponse)
                append("state", response.data.state)
            }

            val verifierResponse = submitForm(
                response.responseUri,
                parameters,
            )
            when (verifierResponse.status) {
                HttpStatusCode.OK -> DispatchOutcome.VerifierResponse.Accepted(null)
                else -> DispatchOutcome.VerifierResponse.Rejected
            }
        }

    override suspend fun encodeRedirectURI(
        request: ResolvedRequestObject,
        consensus: Consensus,
    ): DispatchOutcome.RedirectURI {
        val uri = when (val response = request.responseWith(consensus)) {
            is Fragment -> response.encodeRedirectURI()
            is FragmentJwt -> response.encodeRedirectURI(checkNotNull(holderId), signer)
            is Query -> response.encodeRedirectURI()
            is QueryJwt -> response.encodeRedirectURI(checkNotNull(holderId), signer)
            else -> error("Unexpected response $response")
        }
        return DispatchOutcome.RedirectURI(uri)
    }
}

internal fun Query.encodeRedirectURI(): URI =
    with(redirectUri.toUri().buildUpon()) {
        DirectPostForm.of(data).forEach { (key, value) -> appendQueryParameter(key, value) }
        build()
    }.toURI()

internal fun QueryJwt.encodeRedirectURI(
    holderId: String,
    signer: AuthorizationResponseSigner?,
): URI =
    with(redirectUri.toUri().buildUpon()) {
        val joseResponse = signEncryptResponse(holderId, signer, jarmOption, data)
        appendQueryParameter("response", joseResponse)
        appendQueryParameter("state", data.state)
        build()
    }.toURI()

internal fun Fragment.encodeRedirectURI(): URI =
    with(redirectUri.toUri().buildUpon()) {
        val encodedFragment = DirectPostForm.of(data).map { (key, value) ->
            val encodedKey = UriCodec.encode(key, null)
            val encodedValue = UriCodec.encodeOrNull(value, null)
            "$encodedKey=$encodedValue"
        }.joinToString(separator = "&")
        encodedFragment(encodedFragment)
        build()
    }.toURI()

internal fun FragmentJwt.encodeRedirectURI(
    holderId: String,
    signer: AuthorizationResponseSigner?,
): URI =
    with(redirectUri.toUri().buildUpon()) {
        val joseResponse = signEncryptResponse(holderId, signer, jarmOption, data)
        val encodedFragment =
            mapOf(
                "response" to joseResponse,
                "state" to data.state,
            ).map { (key, value) ->
                val encodedKey = UriCodec.encode(key, null)
                val encodedValue = UriCodec.encodeOrNull(value, null)
                "$encodedKey=$encodedValue"
            }.joinToString(separator = "&")
        encodedFragment(encodedFragment)
        build()
    }.toURI()

/**
 * An object responsible for encoding a [AuthorizationResponsePayload] into
 * HTTP form
 */
internal object DirectPostForm {

    private const val PRESENTATION_SUBMISSION_FORM_PARAM = "presentation_submission"
    private const val VP_TOKEN_FORM_PARAM = "vp_token"
    private const val STATE_FORM_PARAM = "state"
    private const val ID_TOKEN_FORM_PARAM = "id_token"
    private const val ERROR_FORM_PARAM = "error"
    private const val ERROR_DESCRIPTION_FORM_PARAM = "error_description"

    fun of(p: AuthorizationResponsePayload): Map<String, String> {
        fun ps(ps: PresentationSubmission) = Json.encodeToString<PresentationSubmission>(ps)

        return when (p) {
            is AuthorizationResponsePayload.SiopAuthentication -> mapOf(
                ID_TOKEN_FORM_PARAM to p.idToken,
                STATE_FORM_PARAM to p.state,
            )

            is AuthorizationResponsePayload.OpenId4VPAuthorization -> mapOf(
                VP_TOKEN_FORM_PARAM to p.vpToken,
                PRESENTATION_SUBMISSION_FORM_PARAM to ps(p.presentationSubmission),
                STATE_FORM_PARAM to p.state,
            )

            is AuthorizationResponsePayload.SiopOpenId4VPAuthentication -> mapOf(
                ID_TOKEN_FORM_PARAM to p.idToken,
                VP_TOKEN_FORM_PARAM to p.vpToken,
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
