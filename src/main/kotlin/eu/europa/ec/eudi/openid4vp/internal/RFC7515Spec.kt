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
package eu.europa.ec.eudi.openid4vp.internal

import com.nimbusds.jwt.SignedJWT
import kotlinx.serialization.json.*

internal object RFC7515Spec {

    const val JWS_JSON_SYNTAX_PAYLOAD = "payload"
    const val JWS_JSON_SYNTAX_SIGNATURE = "signature"
    const val JWS_JSON_SYNTAX_SIGNATURES = "signatures"
    const val JWS_JSON_SYNTAX_HEADER = "header"
    const val JWS_JSON_SYNTAX_PROTECTED_HEADER = "protected"
}

internal data class Header(
    val protected: Base64UrlNoPadding? = null,
    val unProtected: JsonObject? = null,
) {
    init {
        require(protected != null || unProtected != null) {
            "At least one of protected or un protected parts of the header must be set"
        }
    }
}

internal data class JWSSignature(
    val header: Header,
    val signature: Base64UrlNoPadding,
)

internal data class Base64UrlNoPadding private constructor(val encoded: String) {

    override fun toString(): String = encoded

    companion object {

        operator fun invoke(value: String): Result<Base64UrlNoPadding> = runCatching {
            require(value.isNotBlank()) { "Value must not be empty" }
            // Try to parse the passed value as base64 url encoded no-padding string
            base64UrlNoPadding.decode(value)
            Base64UrlNoPadding(value)
        }
    }
}

internal data class JwsSigned(
    val payload: Base64UrlNoPadding,
    val signatures: List<JWSSignature>,
) {

    init {
        require(!signatures.isEmpty()) { "At least one signature is required" }
    }

    companion object {

        /**
         * Parses an input string representing a JWS in compact form into a [JwsSigned].
         */
        fun from(compact: String): Result<JwsSigned> = runCatching {
            require(compact.isNotBlank()) { "Input must not be empty" }
            compact.split(".").let { parts ->
                require(parts.size == 3) { "Input must be a JWS in compact form" }
                val jwsJsonObject = buildJsonObject {
                    put(RFC7515Spec.JWS_JSON_SYNTAX_HEADER, parts[0])
                    put(RFC7515Spec.JWS_JSON_SYNTAX_PAYLOAD, parts[1])
                    put(RFC7515Spec.JWS_JSON_SYNTAX_SIGNATURE, parts[2])
                }
                return from(jwsJsonObject)
            }
        }

        /**
         * Parses an input [JsonObject] representing a JWS in JSON serialization (general or flattened) into
         * a [JwsSigned].
         */
        fun from(jwsJsonObject: JsonObject): Result<JwsSigned> = runCatching {
            val maybeSignatures = jwsJsonObject[RFC7515Spec.JWS_JSON_SYNTAX_SIGNATURES]
            val maybeSignature = jwsJsonObject[RFC7515Spec.JWS_JSON_SYNTAX_SIGNATURE]
            val jwsSignatures = maybeSignature
                ?.let { listOf(signatureFromFlattened(jwsJsonObject)) }
                ?: maybeSignatures?.let { signaturesFromGeneral(jwsJsonObject) }
                ?: throw IllegalArgumentException("No signatures found!")

            val payload = payload(jwsJsonObject)

            JwsSigned(payload, jwsSignatures)
        }

        private fun payload(jwsJsonObject: JsonObject): Base64UrlNoPadding {
            val maybePayload = jwsJsonObject[RFC7515Spec.JWS_JSON_SYNTAX_PAYLOAD]
                .mustBeNotNullString(RFC7515Spec.JWS_JSON_SYNTAX_PAYLOAD)
            return Base64UrlNoPadding(maybePayload.content).getOrThrow()
        }

        private fun signatureFromFlattened(jwsJsonObject: JsonObject): JWSSignature {
            val signature = jwsJsonObject[RFC7515Spec.JWS_JSON_SYNTAX_SIGNATURE]
                .mustBeNotNullString(RFC7515Spec.JWS_JSON_SYNTAX_SIGNATURE)

            val maybeProtectedHeader = jwsJsonObject[RFC7515Spec.JWS_JSON_SYNTAX_PROTECTED_HEADER]
            val maybeHeader = jwsJsonObject[RFC7515Spec.JWS_JSON_SYNTAX_HEADER]

            return JWSSignature(
                header = Header(
                    protected = maybeProtectedHeader?.let {
                        require(it is JsonPrimitive) { "Protected header must be a String" }
                        Base64UrlNoPadding(it.content).getOrThrow()
                    },
                    unProtected = maybeHeader?.let {
                        require(it is JsonObject) { "Un protected header must be a JSON object" }
                        it.jsonObject
                    },
                ),
                signature = Base64UrlNoPadding(signature.content).getOrThrow(),
            )
        }

        private fun signaturesFromGeneral(jwsJsonObject: JsonObject): List<JWSSignature> {
            val maybeSignatures = jwsJsonObject["signatures"]
            require(maybeSignatures != null) { "No signatures found!" }
            require(maybeSignatures is JsonArray) { "Signatures expected to be an array but was not!" }
            return maybeSignatures.map { signature ->
                require(signature is JsonObject) { "Signature expected to be a JSON object but was not!" }
                signatureFromFlattened(signature)
            }
        }

        private fun JsonElement?.mustBeNotNullString(elementName: String): JsonPrimitive {
            require(this != null) { "No $elementName found!" }
            require(this is JsonPrimitive && this !is JsonNull) { "$elementName must be a not null string" }
            return this
        }
    }
}

internal fun SignedJWT.toJwsFlattenedJsonObject(): JsonObject = buildJsonObject {
    put(RFC7515Spec.JWS_JSON_SYNTAX_PROTECTED_HEADER, header.toBase64URL().toString())
    put(RFC7515Spec.JWS_JSON_SYNTAX_PAYLOAD, payload.toBase64URL().toString())
    put(RFC7515Spec.JWS_JSON_SYNTAX_SIGNATURE, signature.toString())
}

internal fun SignedJWT.toJwsGeneralJsonObject(): JsonObject = buildJsonObject {
    put(RFC7515Spec.JWS_JSON_SYNTAX_PAYLOAD, payload.toBase64URL().toString())
    put(
        RFC7515Spec.JWS_JSON_SYNTAX_SIGNATURES,
        buildJsonArray {
            add(
                buildJsonObject {
                    put(RFC7515Spec.JWS_JSON_SYNTAX_PROTECTED_HEADER, header.toBase64URL().toString())
                    put(RFC7515Spec.JWS_JSON_SYNTAX_SIGNATURE, signature.toString())
                },
            )
        },
    )
}
