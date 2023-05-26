package eu.europa.ec.euidw.openid4vp.internal.dispatch

import com.eygraber.uri.Uri
import com.eygraber.uri.toUri
import com.nimbusds.oauth2.sdk.id.State
import eu.europa.ec.euidw.openid4vp.AuthorizationResponse
import eu.europa.ec.euidw.openid4vp.AuthorizationResponsePayload
import eu.europa.ec.euidw.openid4vp.DispatchOutcome
import eu.europa.ec.euidw.openid4vp.RequestValidationError
import io.ktor.http.*
import io.ktor.util.*
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import java.net.URI

class DefaultDispatcherTest {

    @Nested
    @DisplayName("In query response")
    inner class QueryResponse {

        private val dispatcher = DefaultDispatcher { _, _ -> error("Not used") }
        private val redirectUriBase = URI("https://foo.bar")

        @Test
        fun `when no consensus, redirect_uri must contain an error query parameter`() = runBlocking {
            val state = State().value
            val data = AuthorizationResponsePayload.NoConsensusResponseData(state)
            testQueryResponse(data) {
                assertEquals(
                    AuthorizationRequestErrorCode.USER_CANCELLED.code,
                    getQueryParameter("error"),
                )
            }
        }

        @Test
        fun `when invalid request, redirect_uri must contain an error query parameter`() = runBlocking {
            val state = State().value
            val error = RequestValidationError.MissingNonce
            val data = AuthorizationResponsePayload.InvalidRequest(error, state)
            val expectedErrorCode = AuthorizationRequestErrorCode.fromError(error)
            testQueryResponse(data) {
                assertEquals(expectedErrorCode.code, getQueryParameter("error"))
            }
        }

        @Test
        fun `when response for SIOPAuthentication, redirect_uri must contain an id_token query parameter`() =
            runBlocking {
                val state = State().value
                val dummyJwt = "dummy"
                val data = AuthorizationResponsePayload.SiopAuthenticationResponse(dummyJwt, state)
                testQueryResponse(data) {
                    assertEquals(dummyJwt, getQueryParameter("id_token"))
                }
            }

        private fun testQueryResponse(
            data: AuthorizationResponsePayload,
            assertions: Uri.() -> Unit,
        ) = runBlocking {
            val response = AuthorizationResponse.Query(redirectUri = redirectUriBase, data = data)
            val dispatchOutcome = dispatcher.dispatch(response)
            assertTrue(dispatchOutcome is DispatchOutcome.RedirectURI)
            val redirectUri = (dispatchOutcome as DispatchOutcome.RedirectURI).value.toUri()
                .also { println(it) }
                .also(assertions)
            assertEquals(data.state, redirectUri.getQueryParameter("state"))
        }
    }

    @Nested
    @DisplayName("In fragment response")
    inner class FragmentResponse {

        private val dispatcher = DefaultDispatcher { _, _ -> error("Not used") }
        private val redirectUriBase = URI("https://foo.bar")

        @Test
        fun `when no consensus, fragment must contain an error`() = runBlocking {
            val state = State().value
            val data = AuthorizationResponsePayload.NoConsensusResponseData(state)
            testFragmentResponse(data) { fragmentData ->
                assertEquals(AuthorizationRequestErrorCode.USER_CANCELLED.code, fragmentData["error"])
            }
        }

        @Test
        fun `when invalid request, fragment must contain an error`() = runBlocking {
            val state = State().value
            val error = RequestValidationError.MissingNonce
            val data = AuthorizationResponsePayload.InvalidRequest(error, state)
            val expectedErrorCode = AuthorizationRequestErrorCode.fromError(error)
            testFragmentResponse(data) { fragmentData ->
                assertEquals(expectedErrorCode.code, fragmentData["error"])
            }
        }

        @Test
        fun `when SIOPAuthentication, fragment must contain an id_token`() = runBlocking {
            val state = State().value
            val dummyJwt = "dummy"
            val data = AuthorizationResponsePayload.SiopAuthenticationResponse(dummyJwt, state)
            testFragmentResponse(data) { fragmentData ->
                assertEquals(dummyJwt, fragmentData["id_token"])
            }
        }

        private fun testFragmentResponse(
            data: AuthorizationResponsePayload,
            assertions: (Map<String, String>) -> Unit,
        ) = runBlocking {
            val response = AuthorizationResponse.Fragment(redirectUri = redirectUriBase, data = data)
            val dispatchOutcome = dispatcher.dispatch(response)
            assertTrue(dispatchOutcome is DispatchOutcome.RedirectURI)
            val redirectUri = (dispatchOutcome as DispatchOutcome.RedirectURI).value.toUri()
                .also { println(it) }

            assertNotNull(redirectUri.fragment)
            val map = redirectUri.fragment!!.parseUrlEncodedParameters().toMap().mapValues { it.value.first() }
            map.also(assertions)
            assertEquals(data.state, map["state"])
        }
    }
}
