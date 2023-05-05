package eu.europa.ec.euidw.openid4vp

import kotlinx.coroutines.runBlocking
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

    val json: Json by lazy { Json { ignoreUnknownKeys = true } }

    val walletConfig = WalletOpenId4VPConfig(
        presentationDefinitionUriSupported = true,
        supportedClientIdScheme = SupportedClientIdScheme.IsoX509,
        vpFormatsSupported = emptyList()
    )

    val pd = readFileAsText("presentation-definition/basic_example.json")
        ?.replace("\r\n", "")
        ?.replace("\r", "")
        ?.replace("\n", "")
        ?.replace("  ", "")
        ?.also { URLEncoder.encode(it, "UTF-8") }

    val resolver = AuthorizationRequestResolver.make(walletConfig)

    @Test
    fun `vp token auth request`() = runBlocking {
        val authRequest =
            "https://client.example.org/universal-link?" +
                    "response_type=vp_token" +
                    "&client_id=https%3A%2F%2Fclient.example.org%2Fcb" +
                    "&client_id_scheme=redirect_uri" +
                    "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                    "&nonce=n-0S6_WzA2Mj" +
                    "&presentation_definition=$pd" +
                    "&client_metadata=%7B%22jwks_uri%22%3A%20%22https%3A%2F%2Fjwk%22%2C%22id_token_signed_response_alg%22%3A%20%22RS256%22%2C%22id_token_encrypted_response_alg%22%3A%20%22RS256%22%2C%22id_token_encrypted_response_enc%22%3A%20%22A128CBC-HS256%22%2C%22subject_syntax_types_supported%22%3A%20%5B%22urn%3Aietf%3Aparams%3Aoauth%3Ajwk-thumbprint%22%2C%22did%3Aexample%22%2C%22did%3Akey%22%5D%7D"

        val authReq = SiopId4VPRequest.make(authRequest).getOrThrow().also { println(it) }
        val resolvedRequest = resolver.resolveRequest(authReq).getOrThrow()
        assertTrue { resolvedRequest is ResolvedRequestData.VpTokenRequestData }
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
                    "&client_metadata=%7B%22jwks_uri%22%3A%20%22https%3A%2F%2Fjwk%22%2C%22id_token_signed_response_alg%22%3A%20%22RS256%22%2C%22id_token_encrypted_response_alg%22%3A%20%22RS256%22%2C%22id_token_encrypted_response_enc%22%3A%20%22A128CBC-HS256%22%2C%22subject_syntax_types_supported%22%3A%20%5B%22urn%3Aietf%3Aparams%3Aoauth%3Ajwk-thumbprint%22%2C%22did%3Aexample%22%2C%22did%3Akey%22%5D%7D"

        val authReq = SiopId4VPRequest.make(authRequest).getOrThrow().also { println(it) }
        val resolvedRequest = resolver.resolveRequest(authReq).getOrThrow()
        assertTrue { resolvedRequest is ResolvedRequestData.IdTokenRequestData }
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
                    "&presentation_definition=$pd" +
                    "&client_metadata=%7B%22jwks_uri%22%3A%20%22https%3A%2F%2Fjwk%22%2C%22id_token_signed_response_alg%22%3A%20%22RS256%22%2C%22id_token_encrypted_response_alg%22%3A%20%22RS256%22%2C%22id_token_encrypted_response_enc%22%3A%20%22A128CBC-HS256%22%2C%22subject_syntax_types_supported%22%3A%20%5B%22urn%3Aietf%3Aparams%3Aoauth%3Ajwk-thumbprint%22%2C%22did%3Aexample%22%2C%22did%3Akey%22%5D%7D"

        val authReq = SiopId4VPRequest.make(authRequest).getOrThrow().also { println(it) }
        val resolvedRequest = resolver.resolveRequest(authReq).getOrThrow()
        assertTrue { resolvedRequest is ResolvedRequestData.IdAndVPTokenRequestData }
    }

    @Test
    fun `JAR - vp token auth request`() = runBlocking {
        val authRequest = "http://localhost:8080/public_url?client_id=Verifier&request=eyJraWQiOiIzOWY0NGQzOS0wMzQ4LTRmNzktYjQ1Yy1jNTExMDkyNTU1NjYiLCJhbGciOiJSUzI1NiJ9.eyJyZXNwb25zZV91cmkiOiJodHRwczovL2ZvbyIsImNsaWVudF9pZF9zY2hlbWUiOiJwcmUtcmVnaXN0ZXJlZCIsInJlc3BvbnNlX3R5cGUiOiJ2cF90b2tlbiIsIm5vbmNlIjoiSEhqRDdiMGxMQVh0X0VNVk5EU1c2cHl2blowM05yYlJtSzBKMFJMUHozSlNZY01jMGhfeVZmYkd3VDRuWWtRYzNFR0FYWFNWS1pITkZmNGs5N3ZrdHciLCJjbGllbnRfaWQiOiJWZXJpZmllciIsInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdC5qd3QiLCJhdWQiOiJodHRwczovL3NlbGYtaXNzdWVkLm1lL3YyIiwic2NvcGUiOiIiLCJwcmVzZW50YXRpb25fZGVmaW5pdGlvbiI6eyJpZCI6IjMyZjU0MTYzLTcxNjYtNDhmMS05M2Q4LWZmMjE3YmRiMDY1MyIsImlucHV0X2Rlc2NyaXB0b3JzIjpbeyJpZCI6ImJhbmthY2NvdW50X2lucHV0IiwibmFtZSI6IkZ1bGwgQmFuayBBY2NvdW50IFJvdXRpbmcgSW5mb3JtYXRpb24iLCJwdXJwb3NlIjoiV2UgY2FuIG9ubHkgcmVtaXQgcGF5bWVudCB0byBhIGN1cnJlbnRseS12YWxpZCBiYW5rIGFjY291bnQsIHN1Ym1pdHRlZCBhcyBhbiBBQkEgUlROICsgQWNjdCAgb3IgSUJBTi4iLCJjb25zdHJhaW50cyI6eyJmaWVsZHMiOlt7InBhdGgiOlsiJC5jcmVkZW50aWFsU2NoZW1hLmlkIiwiJC52Yy5jcmVkZW50aWFsU2NoZW1hLmlkIl0sImZpbHRlciI6eyJ0eXBlIjoic3RyaW5nIiwiY29uc3QiOiJodHRwczovL2Jhbmstc3RhbmRhcmRzLmV4YW1wbGUuY29tL2Z1bGxhY2NvdW50cm91dGUuanNvbiJ9fSx7InBhdGgiOlsiJC5pc3N1ZXIiLCIkLnZjLmlzc3VlciIsIiQuaXNzIl0sInB1cnBvc2UiOiJXZSBjYW4gb25seSB2ZXJpZnkgYmFuayBhY2NvdW50cyBpZiB0aGV5IGFyZSBhdHRlc3RlZCBieSBhIHRydXN0ZWQgYmFuaywgYXVkaXRvciwgb3IgcmVndWxhdG9yeSBhdXRob3JpdHkuIiwiZmlsdGVyIjp7InR5cGUiOiJzdHJpbmciLCJwYXR0ZXJuIjoiZGlkOmV4YW1wbGU6MTIzfGRpZDpleGFtcGxlOjQ1NiJ9LCJpbnRlbnRfdG9fcmV0YWluIjp0cnVlfV19fSx7ImlkIjoidXNfcGFzc3BvcnRfaW5wdXQiLCJuYW1lIjoiVVMgUGFzc3BvcnQiLCJjb25zdHJhaW50cyI6eyJmaWVsZHMiOlt7InBhdGgiOlsiJC5jcmVkZW50aWFsU2NoZW1hLmlkIiwiJC52Yy5jcmVkZW50aWFsU2NoZW1hLmlkIl0sImZpbHRlciI6eyJ0eXBlIjoic3RyaW5nIiwiY29uc3QiOiJodWI6Ly9kaWQ6Zm9vOjEyMy9Db2xsZWN0aW9ucy9zY2hlbWEudXMuZ292L3Bhc3Nwb3J0Lmpzb24ifX0seyJwYXRoIjpbIiQuY3JlZGVudGlhbFN1YmplY3QuYmlydGhfZGF0ZSIsIiQudmMuY3JlZGVudGlhbFN1YmplY3QuYmlydGhfZGF0ZSIsIiQuYmlydGhfZGF0ZSJdLCJmaWx0ZXIiOnsidHlwZSI6InN0cmluZyIsImZvcm1hdCI6ImRhdGUifX1dfX1dfSwic3RhdGUiOiI5WTdNbnNEYVhBa2djejBwR19oVTFoUGZlQkVlTzFMaWJrWDdab3VLUHB3a05DNmI3WW1laW40MUN1VWszLUVvekw2TXVYcVhtcjVnTzRlaGNER0VxdyIsImlhdCI6MTY4MjcwNzE3OCwiY2xpZW50X21ldGFkYXRhIjp7Imp3a3NfdXJpIjoiaHR0cHM6Ly9qd2siLCJpZF90b2tlbl9zaWduZWRfcmVzcG9uc2VfYWxnIjoiUlMyNTYiLCJpZF90b2tlbl9lbmNyeXB0ZWRfcmVzcG9uc2VfYWxnIjoiUlMyNTYiLCJpZF90b2tlbl9lbmNyeXB0ZWRfcmVzcG9uc2VfZW5jIjoiQTEyOENCQy1IUzI1NiIsInN1YmplY3Rfc3ludGF4X3R5cGVzX3N1cHBvcnRlZCI6WyJ1cm46aWV0ZjpwYXJhbXM6b2F1dGg6andrLXRodW1icHJpbnQiLCJkaWQ6ZXhhbXBsZSIsImRpZDprZXkiXX19.jgrGjBcDTP5NlON2iYDQOdbr8h5vKLlbROeqg5JbBzRt3o0NIdb-KTCyB5msO9nLjVCnG6GnxfoUgOxUwpl1eKAvI0jpNDwba0jKFZec9AvBT-nSrMGrLKBEj83l2-yV8k1dH-CxKw19_td2bzfUjTYE_jJQPzpQ3ghLRUKVGslOOiScNq39L02O2eMOC00nxkMq6bBAzHUAcBt4-eZ4xd8Chgq7mqsx-phsiMCQ2sPEXTNNECreQrGDVnWAfRKoHVIfzD7ibKhJb8owN2Zs8KyFpMggdaeLHZ2Ce8VoqFFguuIlP8kf9r1p9KgF2gywIbdm0NPzbReWGNZWBiYj_g"
        val authReq = SiopId4VPRequest.make(authRequest).getOrThrow().also { println(it) }
        val resolvedRequest = resolver.resolveRequest(authReq).getOrThrow()
        assertTrue { resolvedRequest is ResolvedRequestData.VpTokenRequestData }
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
                    "&client_metadata=%7B%22jwks_uri%22%3A%20%22https%3A%2F%2Fjwk%22%2C%22id_token_signed_response_alg%22%3A%20%22RS256%22%2C%22id_token_encrypted_response_alg%22%3A%20%22RS256%22%2C%22id_token_encrypted_response_enc%22%3A%20%22A128CBC-HS256%22%2C%22subject_syntax_types_supported%22%3A%20%5B%22urn%3Aietf%3Aparams%3Aoauth%3Ajwk-thumbprint%22%2C%22did%3Aexample%22%2C%22did%3Akey%22%5D%7D"


        var exception = assertFailsWith<AuthorizationRequestValidationException> {
            val authReq = SiopId4VPRequest.make(authRequest).getOrThrow().also { println(it) }
            resolver.resolveRequest(authReq).getOrThrow()
        }
        assertTrue {  exception.error is SiopId4VPRequestValidationError.UnsupportedResponseType }

        authRequest =
            "https://client.example.org/universal-link?" +
                    "response_type=id_tokens" +
                    "&client_id=https%3A%2F%2Fclient.example.org%2Fcb" +
                    "&client_id_scheme=redirect_uri" +
                    "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                    "&nonce=n-0S6_WzA2Mj" +
                    "&client_metadata=%7B%22jwks_uri%22%3A%20%22https%3A%2F%2Fjwk%22%2C%22id_token_signed_response_alg%22%3A%20%22RS256%22%2C%22id_token_encrypted_response_alg%22%3A%20%22RS256%22%2C%22id_token_encrypted_response_enc%22%3A%20%22A128CBC-HS256%22%2C%22subject_syntax_types_supported%22%3A%20%5B%22urn%3Aietf%3Aparams%3Aoauth%3Ajwk-thumbprint%22%2C%22did%3Aexample%22%2C%22did%3Akey%22%5D%7D"

        exception = assertFailsWith<AuthorizationRequestValidationException> {
            val authReq = SiopId4VPRequest.make(authRequest).getOrThrow().also { println(it) }
            resolver.resolveRequest(authReq).getOrThrow()
        }
        assertTrue {  exception.error is SiopId4VPRequestValidationError.UnsupportedResponseType }

    }

    @Test
    fun `nonce validation`() = runBlocking {
        var authRequest =
            "https://client.example.org/universal-link?" +
                    "response_type=id_token" +
                    "&client_id=https%3A%2F%2Fclient.example.org%2Fcb" +
                    "&client_id_scheme=redirect_uri" +
                    "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                    "&client_metadata=%7B%22jwks_uri%22%3A%20%22https%3A%2F%2Fjwk%22%2C%22id_token_signed_response_alg%22%3A%20%22RS256%22%2C%22id_token_encrypted_response_alg%22%3A%20%22RS256%22%2C%22id_token_encrypted_response_enc%22%3A%20%22A128CBC-HS256%22%2C%22subject_syntax_types_supported%22%3A%20%5B%22urn%3Aietf%3Aparams%3Aoauth%3Ajwk-thumbprint%22%2C%22did%3Aexample%22%2C%22did%3Akey%22%5D%7D"


        var exception = assertFailsWith<AuthorizationRequestValidationException> {
            val authReq = SiopId4VPRequest.make(authRequest).getOrThrow().also { println(it) }
            resolver.resolveRequest(authReq).getOrThrow()
        }
        assertTrue {  exception.error is SiopId4VPRequestValidationError.MissingNonce }
    }

    @Test
    fun `client_id validation`() = runBlocking {
        var authRequest =
            "https://client.example.org/universal-link?" +
                    "response_type=id_token" +
                    "&client_id_scheme=redirect_uri" +
                    "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                    "&nonce=n-0S6_WzA2Mj" +
                    "&client_metadata=%7B%22jwks_uri%22%3A%20%22https%3A%2F%2Fjwk%22%2C%22id_token_signed_response_alg%22%3A%20%22RS256%22%2C%22id_token_encrypted_response_alg%22%3A%20%22RS256%22%2C%22id_token_encrypted_response_enc%22%3A%20%22A128CBC-HS256%22%2C%22subject_syntax_types_supported%22%3A%20%5B%22urn%3Aietf%3Aparams%3Aoauth%3Ajwk-thumbprint%22%2C%22did%3Aexample%22%2C%22did%3Akey%22%5D%7D"


        var exception = assertFailsWith<AuthorizationRequestValidationException> {
            val authReq = SiopId4VPRequest.make(authRequest).getOrThrow().also { println(it) }
            resolver.resolveRequest(authReq).getOrThrow()
        }
        assertTrue {  exception.error is SiopId4VPRequestValidationError.MissingClientId }
    }

    fun readFileAsText(fileName: String) : String {
        return json.decodeFromStream<JsonObject>(load(fileName)).jsonObject.toString()
    }

    fun load(f: String): InputStream =
        AuthorizationRequestResolverTest::class.java.classLoader.getResourceAsStream(f)

}