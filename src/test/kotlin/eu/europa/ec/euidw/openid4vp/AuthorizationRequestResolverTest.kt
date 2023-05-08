package eu.europa.ec.euidw.openid4vp

import com.nimbusds.oauth2.sdk.id.State
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromStream
import kotlinx.serialization.json.jsonObject
import java.io.InputStream
import java.net.URLEncoder
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class AuthorizationRequestResolverTest {

    private val json: Json by lazy { Json { ignoreUnknownKeys = true } }

    private val walletConfig = WalletOpenId4VPConfig(
        presentationDefinitionUriSupported = true,
        supportedClientIdScheme = SupportedClientIdScheme.IsoX509,
        vpFormatsSupported = emptyList()
    )

    private val pd = readFileAsText("presentation-definition/basic_example.json")
        ?.replace("\r\n", "")
        ?.replace("\r", "")
        ?.replace("\n", "")
        ?.replace("  ", "")
        ?.also { URLEncoder.encode(it, "UTF-8") }

    private val resolver = AuthorizationRequestResolver.make(walletConfig)

    private val CLIENT_METADATA_JWKS_INLINE = "%7B%20%22jwks%22%3A%20%7B%20%22keys%22%3A%20%5B%20%7B%20%22kty%22%3A%20%22RSA%22%2C%20%22e%22%3A%20%22AQAB%22%2C%20%22use%22%3A%20%22sig%22%2C%20%22kid%22%3A%20%22a4e1bbe6-26e8-480b-a364-f43497894453%22%2C%20%22iat%22%3A%201683559586%2C%20%22n%22%3A%20%22xHI9zoXS-fOAFXDhDmPMmT_UrU1MPimy0xfP-sL0Iu4CQJmGkALiCNzJh9v343fqFT2hfrbigMnafB2wtcXZeEDy6Mwu9QcJh1qLnklW5OOdYsLJLTyiNwMbLQXdVxXiGby66wbzpUymrQmT1v80ywuYd8Y0IQVyteR2jvRDNxy88bd2eosfkUdQhNKUsUmpODSxrEU2SJCClO4467fVdPng7lyzF2duStFeA2vUkZubor3EcrJ72JbZVI51YDAqHQyqKZIDGddOOvyGUTyHz9749bsoesqXHOugVXhc2elKvegwBik3eOLgfYKJwisFcrBl62k90RaMZpXCxNO4Ew%22%20%7D%20%5D%20%7D%2C%20%22id_token_encrypted_response_alg%22%3A%20%22RS256%22%2C%20%22id_token_encrypted_response_enc%22%3A%20%22A128CBC-HS256%22%2C%20%22subject_syntax_types_supported%22%3A%20%5B%20%22urn%3Aietf%3Aparams%3Aoauth%3Ajwk-thumbprint%22%2C%20%22did%3Aexample%22%2C%20%22did%3Akey%22%20%5D%2C%20%22id_token_signed_response_alg%22%3A%20%22RS256%22%20%7D"

    private val CLIENT_METADATA_JWKS_URI = "%7B%20%22jwks%22%3A%20%7B%20%22keys%22%3A%20%5B%20%7B%20%22kty%22%3A%20%22RSA%22%2C%20%22e%22%3A%20%22AQAB%22%2C%20%22use%22%3A%20%22sig%22%2C%20%22kid%22%3A%20%22a4e1bbe6-26e8-480b-a364-f43497894453%22%2C%20%22iat%22%3A%201683559586%2C%20%22n%22%3A%20%22xHI9zoXS-fOAFXDhDmPMmT_UrU1MPimy0xfP-sL0Iu4CQJmGkALiCNzJh9v343fqFT2hfrbigMnafB2wtcXZeEDy6Mwu9QcJh1qLnklW5OOdYsLJLTyiNwMbLQXdVxXiGby66wbzpUymrQmT1v80ywuYd8Y0IQVyteR2jvRDNxy88bd2eosfkUdQhNKUsUmpODSxrEU2SJCClO4467fVdPng7lyzF2duStFeA2vUkZubor3EcrJ72JbZVI51YDAqHQyqKZIDGddOOvyGUTyHz9749bsoesqXHOugVXhc2elKvegwBik3eOLgfYKJwisFcrBl62k90RaMZpXCxNO4Ew%22%20%7D%20%5D%20%7D%2C%20%22id_token_encrypted_response_alg%22%3A%20%22RS256%22%2C%20%22id_token_encrypted_response_enc%22%3A%20%22A128CBC-HS256%22%2C%20%22subject_syntax_types_supported%22%3A%20%5B%20%22urn%3Aietf%3Aparams%3Aoauth%3Ajwk-thumbprint%22%2C%20%22did%3Aexample%22%2C%20%22did%3Akey%22%20%5D%2C%20%22id_token_signed_response_alg%22%3A%20%22RS256%22%20%7D"

    private fun genState(): String {
        return State().value
    }

    @Test
    fun `vp token auth request`() = runBlocking {
        val authRequest =
            "https://client.example.org/universal-link?" +
                    "response_type=vp_token" +
                    "&client_id=https%3A%2F%2Fclient.example.org%2Fcb" +
                    "&client_id_scheme=redirect_uri" +
                    "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                    "&nonce=n-0S6_WzA2Mj" +
                    "&state=${genState()}"+
                    "&presentation_definition=$pd" +
                    "&client_metadata=$CLIENT_METADATA_JWKS_INLINE"

        val authReq = AuthorizationRequest.make(authRequest).getOrThrow().also { println(it) }
        val resolvedRequest = resolver.resolveRequest(authReq).getOrThrow()
        assertTrue { resolvedRequest is ResolvedRequestObject.VpTokenRequestObject }
    }

    @Test
    fun `id token auth request`() = runBlocking {
        val authRequest =
            "https://client.example.org/universal-link?" +
                    "response_type=id_token" +
                    "&client_id=https%3A%2F%2Fclient.example.org%2Fcb" +
                    "&client_id_scheme=redirect_uri" +
                    "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                    "&nonce=n-0S6_WzA2Mj" +
                    "&state=${genState()}"+
                    "&scope=openid"+
                    "&client_metadata=$CLIENT_METADATA_JWKS_INLINE"

        val authReq = AuthorizationRequest.make(authRequest).getOrThrow().also { println(it) }
        val resolvedRequest = resolver.resolveRequest(authReq).getOrThrow()
        assertTrue { resolvedRequest is ResolvedRequestObject.IdTokenRequestObject }
    }

    @Test
    fun `id and vp token auth request`() = runBlocking {
        val authRequest =
            "https://client.example.org/universal-link?" +
                    "response_type=id_token vp_token" +
                    "&client_id=https%3A%2F%2Fclient.example.org%2Fcb" +
                    "&client_id_scheme=redirect_uri" +
                    "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                    "&nonce=n-0S6_WzA2Mj" +
                    "&scope=openid"+
                    "&state=${genState()}"+
                    "&presentation_definition=$pd" +
                    "&client_metadata=$CLIENT_METADATA_JWKS_INLINE"

        val authReq = AuthorizationRequest.make(authRequest).getOrThrow().also { println(it) }
        val resolvedRequest = resolver.resolveRequest(authReq).getOrThrow()
        assertTrue { resolvedRequest is ResolvedRequestObject.IdAndVPTokenRequestObject }
    }

    @Test
    fun `JAR auth request, request passed as JWT`() = runBlocking {
        val authRequest =
            "http://localhost:8080/public_url?client_id=Verifier&request=eyJraWQiOiJhNGUxYmJlNi0yNmU4LTQ4MGItYTM2NC1mNDM0OTc4OTQ0NTMiLCJhbGciOiJSUzI1NiJ9.eyJyZXNwb25zZV91cmkiOiJodHRwczovL2ZvbyIsImNsaWVudF9pZF9zY2hlbWUiOiJwcmUtcmVnaXN0ZXJlZCIsInJlc3BvbnNlX3R5cGUiOiJ2cF90b2tlbiIsIm5vbmNlIjoiOFMyNjc1SlZzU0ViaURnYjhqVVFMX3puVy1vSTJROV9keXlDZkZkU1BYQUwzMy1jcDd4c0VYNmdnb1czMlNBcWEyN1BxV0hmRUM3MDJPQ1hjcUd2ckEiLCJjbGllbnRfaWQiOiJWZXJpZmllciIsInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdC5qd3QiLCJhdWQiOiJodHRwczovL3NlbGYtaXNzdWVkLm1lL3YyIiwic2NvcGUiOiIiLCJwcmVzZW50YXRpb25fZGVmaW5pdGlvbiI6eyJpZCI6IjMyZjU0MTYzLTcxNjYtNDhmMS05M2Q4LWZmMjE3YmRiMDY1MyIsImlucHV0X2Rlc2NyaXB0b3JzIjpbeyJpZCI6ImJhbmthY2NvdW50X2lucHV0IiwibmFtZSI6IkZ1bGwgQmFuayBBY2NvdW50IFJvdXRpbmcgSW5mb3JtYXRpb24iLCJwdXJwb3NlIjoiV2UgY2FuIG9ubHkgcmVtaXQgcGF5bWVudCB0byBhIGN1cnJlbnRseS12YWxpZCBiYW5rIGFjY291bnQsIHN1Ym1pdHRlZCBhcyBhbiBBQkEgUlROICsgQWNjdCAgb3IgSUJBTi4iLCJjb25zdHJhaW50cyI6eyJmaWVsZHMiOlt7InBhdGgiOlsiJC5jcmVkZW50aWFsU2NoZW1hLmlkIiwiJC52Yy5jcmVkZW50aWFsU2NoZW1hLmlkIl0sImZpbHRlciI6eyJ0eXBlIjoic3RyaW5nIiwiY29uc3QiOiJodHRwczovL2Jhbmstc3RhbmRhcmRzLmV4YW1wbGUuY29tL2Z1bGxhY2NvdW50cm91dGUuanNvbiJ9fSx7InBhdGgiOlsiJC5pc3N1ZXIiLCIkLnZjLmlzc3VlciIsIiQuaXNzIl0sInB1cnBvc2UiOiJXZSBjYW4gb25seSB2ZXJpZnkgYmFuayBhY2NvdW50cyBpZiB0aGV5IGFyZSBhdHRlc3RlZCBieSBhIHRydXN0ZWQgYmFuaywgYXVkaXRvciwgb3IgcmVndWxhdG9yeSBhdXRob3JpdHkuIiwiZmlsdGVyIjp7InR5cGUiOiJzdHJpbmciLCJwYXR0ZXJuIjoiZGlkOmV4YW1wbGU6MTIzfGRpZDpleGFtcGxlOjQ1NiJ9LCJpbnRlbnRfdG9fcmV0YWluIjp0cnVlfV19fSx7ImlkIjoidXNfcGFzc3BvcnRfaW5wdXQiLCJuYW1lIjoiVVMgUGFzc3BvcnQiLCJjb25zdHJhaW50cyI6eyJmaWVsZHMiOlt7InBhdGgiOlsiJC5jcmVkZW50aWFsU2NoZW1hLmlkIiwiJC52Yy5jcmVkZW50aWFsU2NoZW1hLmlkIl0sImZpbHRlciI6eyJ0eXBlIjoic3RyaW5nIiwiY29uc3QiOiJodWI6Ly9kaWQ6Zm9vOjEyMy9Db2xsZWN0aW9ucy9zY2hlbWEudXMuZ292L3Bhc3Nwb3J0Lmpzb24ifX0seyJwYXRoIjpbIiQuY3JlZGVudGlhbFN1YmplY3QuYmlydGhfZGF0ZSIsIiQudmMuY3JlZGVudGlhbFN1YmplY3QuYmlydGhfZGF0ZSIsIiQuYmlydGhfZGF0ZSJdLCJmaWx0ZXIiOnsidHlwZSI6InN0cmluZyIsImZvcm1hdCI6ImRhdGUifX1dfX1dfSwic3RhdGUiOiJ1LWJuT0Q2RDktSC1KbjVDZUFoVFRQRXB1VlBRN3VIeFVQQ1R4STdaeDVUemxwWGlSTlFaaDh4QkplRnBQdHprQnU0LU5QaXo3SUlNb1BMRXpSOU12USIsImlhdCI6MTY4MzU1OTc0MSwiY2xpZW50X21ldGFkYXRhIjp7Imp3a3MiOnsia2V5cyI6W3sia3R5IjoiUlNBIiwiZSI6IkFRQUIiLCJ1c2UiOiJzaWciLCJraWQiOiJhNGUxYmJlNi0yNmU4LTQ4MGItYTM2NC1mNDM0OTc4OTQ0NTMiLCJpYXQiOjE2ODM1NTk1ODYsIm4iOiJ4SEk5em9YUy1mT0FGWERoRG1QTW1UX1VyVTFNUGlteTB4ZlAtc0wwSXU0Q1FKbUdrQUxpQ056Smg5djM0M2ZxRlQyaGZyYmlnTW5hZkIyd3RjWFplRUR5Nk13dTlRY0poMXFMbmtsVzVPT2RZc0xKTFR5aU53TWJMUVhkVnhYaUdieTY2d2J6cFV5bXJRbVQxdjgweXd1WWQ4WTBJUVZ5dGVSMmp2UkROeHk4OGJkMmVvc2ZrVWRRaE5LVXNVbXBPRFN4ckVVMlNKQ0NsTzQ0NjdmVmRQbmc3bHl6RjJkdVN0RmVBMnZVa1p1Ym9yM0Vjcko3MkpiWlZJNTFZREFxSFF5cUtaSURHZGRPT3Z5R1VUeUh6OTc0OWJzb2VzcVhIT3VnVlhoYzJlbEt2ZWd3QmlrM2VPTGdmWUtKd2lzRmNyQmw2Mms5MFJhTVpwWEN4Tk80RXcifV19LCJpZF90b2tlbl9lbmNyeXB0ZWRfcmVzcG9uc2VfYWxnIjoiUlMyNTYiLCJpZF90b2tlbl9lbmNyeXB0ZWRfcmVzcG9uc2VfZW5jIjoiQTEyOENCQy1IUzI1NiIsInN1YmplY3Rfc3ludGF4X3R5cGVzX3N1cHBvcnRlZCI6WyJ1cm46aWV0ZjpwYXJhbXM6b2F1dGg6andrLXRodW1icHJpbnQiLCJkaWQ6ZXhhbXBsZSIsImRpZDprZXkiXSwiaWRfdG9rZW5fc2lnbmVkX3Jlc3BvbnNlX2FsZyI6IlJTMjU2In19.mID6ks8gNEH6vys_s7SFmKt46_323SFnMwxJJPpFJ2D2Ay75GWZfcmdJgvaxjz1lUfAYoMuhHa1i-A6uKDz-e3-zesXswcKJ8uns38Q5ppcoYStgKNBi8YcA91Odv5jQyBUEkgKHFghgBSTbfXh_O5E2nBsi9BoHMUdc9BwrhtKiT18jTxUayNydIlRqhZXCDZdTn_CO-e9seqqKo0mSg1RST6OidvNjw36E93P-TYVeod8m2WPXMQ_hFVtaduv0W_ntlWA9dAXlQYD3Phy7kMGn_TUfQX0bkLbT4o-cwsbskcmDGNT9pH7MlpOYyj7Ogkaa11lsxnBejhwW72aPjg"
        val authReq = AuthorizationRequest.make(authRequest).getOrThrow().also { println(it) }
        val resolvedRequest = resolver.resolveRequest(authReq).getOrThrow()
        assertTrue { resolvedRequest is ResolvedRequestObject.VpTokenRequestObject }
    }


    @Test
    fun `response type validation`() = runBlocking {
        var authRequest =
            "https://client.example.org/universal-link?" +
                    "response_type=id_token,vp_token" +
                    "&client_id=https%3A%2F%2Fclient.example.org%2Fcb" +
                    "&client_id_scheme=redirect_uri" +
                    "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                    "&nonce=n-0S6_WzA2Mj" +
                    "&state=${genState()}"+
                    "&client_metadata=$CLIENT_METADATA_JWKS_INLINE"


        var exception = assertFailsWith<AuthorizationRequestValidationException> {
            val authReq = AuthorizationRequest.make(authRequest).getOrThrow().also { println(it) }
            resolver.resolveRequest(authReq).getOrThrow()
        }
        assertTrue { exception.error is SiopId4VPRequestValidationError.UnsupportedResponseType }

        authRequest =
            "https://client.example.org/universal-link?" +
                    "response_type=id_tokens" +
                    "&client_id=https%3A%2F%2Fclient.example.org%2Fcb" +
                    "&client_id_scheme=redirect_uri" +
                    "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                    "&nonce=n-0S6_WzA2Mj" +
                    "&state=${genState()}"+
                    "&client_metadata=$CLIENT_METADATA_JWKS_INLINE"

        exception = assertFailsWith<AuthorizationRequestValidationException> {
            val authReq = AuthorizationRequest.make(authRequest).getOrThrow().also { println(it) }
            resolver.resolveRequest(authReq).getOrThrow()
        }
        assertTrue { exception.error is SiopId4VPRequestValidationError.UnsupportedResponseType }

    }

    @Test
    fun `nonce validation`() = runBlocking {
        val authRequest =
            "https://client.example.org/universal-link?" +
                    "response_type=id_token" +
                    "&client_id=https%3A%2F%2Fclient.example.org%2Fcb" +
                    "&client_id_scheme=redirect_uri" +
                    "&state=${genState()}"+
                    "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                    "&client_metadata=$CLIENT_METADATA_JWKS_INLINE"


        val exception = assertFailsWith<AuthorizationRequestValidationException> {
            val authReq = AuthorizationRequest.make(authRequest).getOrThrow().also { println(it) }
            resolver.resolveRequest(authReq).getOrThrow()
        }
        assertTrue { exception.error is SiopId4VPRequestValidationError.MissingNonce }
    }

    @Test
    fun `client_id validation`() = runBlocking {
        val authRequest =
            "https://client.example.org/universal-link?" +
                    "response_type=id_token" +
                    "&client_id_scheme=redirect_uri" +
                    "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                    "&nonce=n-0S6_WzA2Mj" +
                    "&state=${genState()}"+
                    "&client_metadata=$CLIENT_METADATA_JWKS_INLINE"


        val exception = assertFailsWith<AuthorizationRequestValidationException> {
            val authReq = AuthorizationRequest.make(authRequest).also { println(it) }.getOrThrow()
            resolver.resolveRequest(authReq).getOrThrow()
        }
        assertTrue { exception.error is SiopId4VPRequestValidationError.MissingClientId }
    }

    @OptIn(ExperimentalSerializationApi::class)
    fun readFileAsText(fileName: String): String? {
        return load(fileName)?.let { json.decodeFromStream<JsonObject>(it).jsonObject.toString() }
    }

    private fun load(f: String): InputStream? =
        AuthorizationRequestResolverTest::class.java.classLoader.getResourceAsStream(f)

}