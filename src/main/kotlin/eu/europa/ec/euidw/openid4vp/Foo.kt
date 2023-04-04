package eu.europa.ec.euidw.openid4vp

import com.eygraber.uri.Uri
import eu.europa.ec.euidw.prex.PresentationExchange
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import java.net.URLDecoder
import java.net.URLEncoder


val pd = """{
    "id": "vp token example",
    "input_descriptors": [
        {
            "id": "id card credential",
            "format": {
                "ldp_vc": {
                    "proof_type": [
                        "Ed25519Signature2018"
                    ]
                }
            },
            "constraints": {
                "fields": [
                    {
                        "path": [
                            "$.type"
                        ],
                        "filter": {
                            "type": "string",
                            "pattern": "IDCardCredential"
                        }
                    }
                ]
            }
        }
    ]
}""".replace("\n","").replace("  ", "").also { URLEncoder.encode(it, "UTF-8") }


val sample =
    "https://client.example.org/universal-link?" +
            "response_type=vp_token" +
            "&client_id=https%3A%2F%2Fclient.example.org%2Fcb" +
            "&client_id_scheme=redirect_uri" +
            "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
            "&presentation_definition=$pd" +
            "&nonce=n-0S6_WzA2Mj" +
            "&client_metadata=%7B%22vp_formats%22:%7B%22jwt_vp%22:%7B%22alg%22:%5B%22EdDSA%22,%22ES256K%22%5D%7D,%22ldp_vp%22:%7B%22proof_type%22:%5B%22Ed25519Signature2018%22%5D%7D%7D%7D"

private val validator = AuthorizationRequestValidator(PresentationExchange.jsonParser)

fun main() {



    val authReq = AuthorizationRequest.make(sample).getOrThrow().also { println(it) }
    if (authReq is AuthorizationRequest.Oauth2) {
        val data = authReq.data
        val validated = validator.validate(data).getOrThrow()
        println(validated)
    }


}