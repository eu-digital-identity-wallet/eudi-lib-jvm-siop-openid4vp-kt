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
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.http.content.*
import io.ktor.util.*
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import java.net.URI
import java.net.URL
import java.nio.charset.Charset

/**
 * Default implementation of [Dispatcher]
 *
 * @param siopOpenId4VPConfig the wallet configuration
 * @param httpClientFactory factory to obtain [HttpClient]
 */
internal class DefaultDispatcher(
    private val siopOpenId4VPConfig: SiopOpenId4VPConfig,
    private val httpClientFactory: KtorHttpClientFactory,
) : Dispatcher {

    override suspend fun post(
        request: ResolvedRequestObject,
        consensus: Consensus,
    ): DispatchOutcome.VerifierResponse {
        val (responseUri, parameters) = formParameters(request, consensus)
        return httpClientFactory().use { httpClient ->
            submitForm(httpClient, responseUri, parameters)
        }
    }

    private fun formParameters(request: ResolvedRequestObject, consensus: Consensus) =
        when (val response = request.responseWith(consensus)) {
            is DirectPost -> {
                val parameters = DirectPostForm.parametersOf(response.data)
                response.responseUri to parameters
            }

            is DirectPostJwt -> {
                val jarmJwt = siopOpenId4VPConfig.jarmJwt(response.jarmRequirement, response.data)
                val parameters = DirectPostJwtForm.parametersOf(jarmJwt, response.data.state)
                response.responseUri to parameters
            }

            else -> error("Unexpected response $response")
        }

    /**
     * Submits an HTTP Form to [url] with the provided [parameters].
     */
    @OptIn(InternalAPI::class)
    private suspend fun submitForm(
        httpClient: HttpClient,
        url: URL,
        parameters: Parameters,
    ): DispatchOutcome.VerifierResponse {
        val response = httpClient.post(url.toExternalForm()) {
            body = FormData(parameters)
        }

        return when (response.status) {
            HttpStatusCode.OK -> {
                val redirectUri =
                    try {
                        response.body<JsonObject?>()
                            ?.get("redirect_uri")
                            ?.takeIf { it is JsonPrimitive }
                            ?.jsonPrimitive?.contentOrNull
                            ?.let { URI.create(it) }
                    } catch (t: NoTransformationFoundException) {
                        null
                    }
                DispatchOutcome.VerifierResponse.Accepted(redirectUri)
            }

            else -> DispatchOutcome.VerifierResponse.Rejected
        }
    }

    override suspend fun encodeRedirectURI(
        request: ResolvedRequestObject,
        consensus: Consensus,
    ): DispatchOutcome.RedirectURI {
        val uri = when (val response = request.responseWith(consensus)) {
            is Fragment -> response.encodeRedirectURI()
            is FragmentJwt -> response.encodeRedirectURI(siopOpenId4VPConfig)
            is Query -> response.encodeRedirectURI()
            is QueryJwt -> response.encodeRedirectURI(siopOpenId4VPConfig)
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

internal fun QueryJwt.encodeRedirectURI(siopOpenId4VPConfig: SiopOpenId4VPConfig): URI =
    with(redirectUri.toUri().buildUpon()) {
        val jarmJwt = siopOpenId4VPConfig.jarmJwt(jarmRequirement, data)
        appendQueryParameter("response", jarmJwt)
        data.state?.let {
            appendQueryParameter("state", it)
        }
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

internal fun FragmentJwt.encodeRedirectURI(siopOpenId4VPConfig: SiopOpenId4VPConfig): URI =
    with(redirectUri.toUri().buildUpon()) {
        val jarmJwt = siopOpenId4VPConfig.jarmJwt(jarmRequirement, data)
        val encodedFragment =
            buildMap {
                put("response", jarmJwt)
                data.state?.let {
                    put("state", it)
                }
            }.map { (key, value) ->
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

    fun parametersOf(p: AuthorizationResponsePayload): Parameters =
        of(p).let { form ->
            Parameters.build {
                form.entries.forEach { (name, value) -> append(name, value) }
            }
        }

    fun of(p: AuthorizationResponsePayload): Map<String, String> {
        fun ps(ps: PresentationSubmission) = Json.encodeToString<PresentationSubmission>(ps)

        return when (p) {
            is AuthorizationResponsePayload.SiopAuthentication -> buildMap {
                put(ID_TOKEN_FORM_PARAM, p.idToken)
                p.state?.let {
                    put(STATE_FORM_PARAM, it)
                }
            }

            is AuthorizationResponsePayload.OpenId4VPAuthorization -> buildMap {
                put(VP_TOKEN_FORM_PARAM, p.vpToken)
                put(PRESENTATION_SUBMISSION_FORM_PARAM, ps(p.presentationSubmission))
                p.state?.let {
                    put(STATE_FORM_PARAM, it)
                }
            }

            is AuthorizationResponsePayload.SiopOpenId4VPAuthentication -> buildMap {
                put(ID_TOKEN_FORM_PARAM, p.idToken)
                put(VP_TOKEN_FORM_PARAM, p.vpToken)
                put(PRESENTATION_SUBMISSION_FORM_PARAM, ps(p.presentationSubmission))
                p.state?.let {
                    put(STATE_FORM_PARAM, it)
                }
            }

            is AuthorizationResponsePayload.InvalidRequest -> buildMap {
                put(ERROR_FORM_PARAM, AuthorizationRequestErrorCode.fromError(p.error).code)
                put(ERROR_DESCRIPTION_FORM_PARAM, "${p.error}")
                p.state?.let {
                    put(STATE_FORM_PARAM, it)
                }
            }

            is AuthorizationResponsePayload.NoConsensusResponseData -> buildMap {
                put(ERROR_FORM_PARAM, AuthorizationRequestErrorCode.USER_CANCELLED.code)
                p.state?.let {
                    put(STATE_FORM_PARAM, it)
                }
            }
        }
    }
}

internal object DirectPostJwtForm {
    fun parametersOf(jarmJwt: Jwt, state: String?): Parameters =
        Parameters.build {
            append("response", jarmJwt)
            state?.let {
                append("state", it)
            }
        }
}

/**
 * [OutgoingContent] for `application/x-www-form-urlencoded` formatted requests that allows
 * explicitly setting the [Charset] to be used when encoding the request body.
 */
internal class FormData(
    val formData: Parameters,
    val charset: Charset = Charsets.US_ASCII,
) : OutgoingContent.ByteArrayContent() {
    private val content = formData.formUrlEncode().toByteArray(charset)

    override val contentLength: Long = content.size.toLong()
    override val contentType: ContentType =
        if (charset == Charsets.US_ASCII) {
            ContentType.Application.FormUrlEncoded
        } else {
            ContentType.Application.FormUrlEncoded.withCharset(charset)
        }

    override fun bytes(): ByteArray = content
}
