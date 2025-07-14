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
package eu.europa.ec.eudi.openid4vp

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.Base64URL
import eu.europa.ec.eudi.openid4vp.dcql.QueryId
import kotlinx.serialization.json.JsonObject
import java.io.Serializable
import java.net.URI
import java.net.URL

sealed interface SubjectSyntaxType : Serializable {

    @JvmInline
    value class DecentralizedIdentifier(val method: String) : SubjectSyntaxType

    data object JWKThumbprint : SubjectSyntaxType {
        private fun readResolve(): Any = JWKThumbprint
    }
}

@JvmInline
value class Scope private constructor(val value: String) {
    fun items(): List<Scope> = when (value) {
        "" -> emptyList()
        else -> value.split(SEPARATOR).map { Scope(it) }
    }
    operator fun plus(other: Scope): Scope = Scope("$value$SEPARATOR${other.value}")
    operator fun contains(other: Scope): Boolean {
        val thisFlatten = items().flatMap { it.items() }
        val otherFlatten = other.items().flatMap { it.items() }
        return thisFlatten.containsAll(otherFlatten)
    }

    companion object {

        fun List<Scope>.mergeOrNull(): Scope? =
            if (isEmpty()) null
            else fold(EMPTY, Scope::plus)

        val OpenId = Scope("openid")
        private val EMPTY = Scope("")
        private const val SEPARATOR = " "
        fun make(s: String): Scope? = s.trim()
            .takeIf { trimmed -> trimmed.split(SEPARATOR).isNotEmpty() }
            ?.let { Scope(it) }
    }
}

enum class ClientIdPrefix {
    /**
     * This value represents the RFC6749 default behavior,
     * i.e., the Client Identifier needs to be known to the Wallet in advance of the Authorization Request
     * The Verifier's metadata is obtained using (RFC7591) or through out-of-band mechanisms.
     */
    PreRegistered,

    /**
     * This value indicates that the Verifier's Redirect URI is also
     * the value of the Client Identifier. In this case,
     * the Authorization Request MUST NOT be signed,
     * the Verifier MAY omit the redirect_uri Authorization Request parameter,
     * and all Client metadata parameters MUST be passed using the client_metadata parameter
     */
    RedirectUri,

    /**
     * This value indicates that the Client Identifier is an Entity Identifier
     * defined in OpenID Federation.
     */
    OpenIdFederation,

    /**
     * This value indicates that the Client Identifier is a DID
     */
    DecentralizedIdentifier,

    /**
     * This Client Identifier Prefix allows the Verifier
     * to authenticate using a JWT that is bound to a certain public key
     */
    VerifierAttestation,

    /**
     * When the Client Identifier Prefix is x509_san_dns, the Client Identifier
     * MUST be a DNS name and match a dNSName Subject Alternative Name (SAN) RFC5280
     * entry in the leaf certificate passed with the request
     */
    X509SanDns,

    /**
     * When the Client Identifier Prefix is x509_hash, the original Client Identifier (the part without the x509_hash: prefix)
     * MUST be a hash and match the hash of the leaf certificate passed with the request.
     * The request MUST be signed with the private key corresponding to the public key in the leaf X.509 certificate of the certificate
     * chain added to the request in the x5c JOSE header parameter RFC7515 of the signed request object.
     */
    X509Hash,

    ;

    fun value(): String = when (this) {
        PreRegistered -> OpenId4VPSpec.CLIENT_ID_PREFIX_PRE_REGISTERED
        RedirectUri -> OpenId4VPSpec.CLIENT_ID_PREFIX_REDIRECT_URI
        OpenIdFederation -> OpenId4VPSpec.CLIENT_ID_PREFIX_OPENID_FEDERATION
        DecentralizedIdentifier -> OpenId4VPSpec.CLIENT_ID_PREFIX_DECENTRALIZED_IDENTIFIER
        VerifierAttestation -> OpenId4VPSpec.CLIENT_ID_PREFIX_VERIFIER_ATTESTATION
        X509SanDns -> OpenId4VPSpec.CLIENT_ID_PREFIX_X509_SAN_DNS
        X509Hash -> OpenId4VPSpec.CLIENT_ID_PREFIX_X509_HASH
    }

    companion object {
        fun make(s: String): ClientIdPrefix? = when (s) {
            OpenId4VPSpec.CLIENT_ID_PREFIX_PRE_REGISTERED -> PreRegistered
            OpenId4VPSpec.CLIENT_ID_PREFIX_REDIRECT_URI -> RedirectUri
            OpenId4VPSpec.CLIENT_ID_PREFIX_OPENID_FEDERATION -> OpenIdFederation
            OpenId4VPSpec.CLIENT_ID_PREFIX_DECENTRALIZED_IDENTIFIER -> DecentralizedIdentifier
            OpenId4VPSpec.CLIENT_ID_PREFIX_VERIFIER_ATTESTATION -> VerifierAttestation
            OpenId4VPSpec.CLIENT_ID_PREFIX_X509_SAN_DNS -> X509SanDns
            OpenId4VPSpec.CLIENT_ID_PREFIX_X509_HASH -> X509Hash
            else -> null
        }
    }
}

/**
 * The Original Client Id of a Verifier, i.e. without a Client Id Prefix.
 */
typealias OriginalClientId = String

/**
 * The Client Id of a Verifier as defined by OpenId4Vp.
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-client-identifier-prefix-an">https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-client-identifier-prefix-an</a>
 */
data class VerifierId(
    val prefix: ClientIdPrefix,
    val originalClientId: OriginalClientId,
) {
    val clientId: String = run {
        val prefix = when (prefix) {
            ClientIdPrefix.PreRegistered -> null
            ClientIdPrefix.RedirectUri -> OpenId4VPSpec.CLIENT_ID_PREFIX_REDIRECT_URI
            ClientIdPrefix.OpenIdFederation -> OpenId4VPSpec.CLIENT_ID_PREFIX_OPENID_FEDERATION
            ClientIdPrefix.DecentralizedIdentifier -> OpenId4VPSpec.CLIENT_ID_PREFIX_DECENTRALIZED_IDENTIFIER
            ClientIdPrefix.VerifierAttestation -> OpenId4VPSpec.CLIENT_ID_PREFIX_VERIFIER_ATTESTATION
            ClientIdPrefix.X509SanDns -> OpenId4VPSpec.CLIENT_ID_PREFIX_X509_SAN_DNS
            ClientIdPrefix.X509Hash -> OpenId4VPSpec.CLIENT_ID_PREFIX_X509_HASH
        }

        buildString {
            if (prefix != null) {
                append(prefix)
                append(OpenId4VPSpec.CLIENT_ID_PREFIX_SEPARATOR)
            }
            append(originalClientId)
        }
    }

    override fun toString(): String = clientId

    companion object {
        fun parse(clientId: String): Result<VerifierId> = runCatching {
            fun invalid(message: String): Nothing = throw IllegalArgumentException(message)

            if (OpenId4VPSpec.CLIENT_ID_PREFIX_SEPARATOR !in clientId) {
                VerifierId(ClientIdPrefix.PreRegistered, clientId)
            } else {
                val parts = clientId.split(OpenId4VPSpec.CLIENT_ID_PREFIX_SEPARATOR, limit = 2)
                val originalClientId = parts[1]
                val prefix = ClientIdPrefix.make(parts[0]) ?: invalid("'$clientId' does not contain a valid Client ID prefix")
                when (prefix) {
                    ClientIdPrefix.PreRegistered -> invalid("'${ClientIdPrefix.PreRegistered}' cannot be used as a Client ID prefix")
                    ClientIdPrefix.RedirectUri -> VerifierId(prefix, originalClientId)
                    ClientIdPrefix.OpenIdFederation -> VerifierId(prefix, originalClientId)
                    ClientIdPrefix.DecentralizedIdentifier -> VerifierId(prefix, originalClientId)
                    ClientIdPrefix.VerifierAttestation -> VerifierId(prefix, originalClientId)
                    ClientIdPrefix.X509SanDns -> VerifierId(prefix, originalClientId)
                    ClientIdPrefix.X509Hash -> VerifierId(prefix, originalClientId)
                }
            }
        }
    }
}

/**
 * @see <a href="https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html">https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html</a>
 */
sealed interface ResponseMode : Serializable {

    /**
     * In this mode, Authorization Response parameters are encoded
     * in the query string added to the redirect_uri when redirecting back to the Client.
     */
    data class Query(val redirectUri: URI) : ResponseMode
    data class QueryJwt(val redirectUri: URI) : ResponseMode

    /**
     * In this mode, Authorization Response parameters
     * are encoded in the fragment added to the redirect_uri when redirecting back to the Client.
     */
    data class Fragment(val redirectUri: URI) : ResponseMode
    data class FragmentJwt(val redirectUri: URI) : ResponseMode
    data class DirectPost(val responseURI: URL) : ResponseMode
    data class DirectPostJwt(val responseURI: URL) : ResponseMode
}

typealias Jwt = String

sealed interface VerifiablePresentation {

    @JvmInline
    value class Generic(val value: String) : VerifiablePresentation

    @JvmInline
    value class JsonObj(val value: JsonObject) : VerifiablePresentation
}

@JvmInline
value class VerifiablePresentations(val value: Map<QueryId, List<VerifiablePresentation>>) {
    init {
        require(value.isNotEmpty())
        require(value.values.all { it.isNotEmpty() })
    }
}

/**
 * The type of the `id_token`
 * the client (verifier party) requested
 */
enum class IdTokenType {
    SubjectSigned,
    AttesterSigned,
}

/**
 * The client's (verifier) requirement to
 * reply to an authorization request with JARM
 */
sealed interface JarmRequirement : Serializable {
    /**
     * Client requires JARM signed response using the [responseSigningAlg]
     * signing algorithm
     */
    data class Signed(val responseSigningAlg: JWSAlgorithm) : JarmRequirement

    /**
     * Client requires JARM encrypted response using the
     * provided [algorithm][responseEncryptionAlg], [encoding method][responseEncryptionEnc]
     * and [client's encryption key][clientKey]
     */
    data class Encrypted(
        val responseEncryptionAlg: JWEAlgorithm,
        val responseEncryptionEnc: EncryptionMethod,
        val clientKey: JWK,
    ) : JarmRequirement

    /**
     * Client requires JARM signed and (then) encrypted
     * using the provided [signing][signed] and [encryption][encryptResponse]
     * specifications
     */
    data class SignedAndEncrypted(val signed: Signed, val encryptResponse: Encrypted) : JarmRequirement
}

sealed interface EncryptionParameters : Serializable {

    data class DiffieHellman(val apu: Base64URL) : EncryptionParameters
}

/**
 * IANA registered Hash Algorithms
 *
 * @see <a href="https://www.iana.org/assignments/named-information/named-information.xhtml">https://www.iana.org/assignments/named-information/named-information.xhtml</a>
 */
@JvmInline
value class HashAlgorithm(val name: String) : Serializable {
    init {
        require(name.isNotEmpty())
    }

    override fun toString(): String = name

    companion object {
        val SHA_256: HashAlgorithm get() = HashAlgorithm("sha-256")
    }
}

@JvmInline
value class TransactionDataType(val value: String) : Serializable {
    init {
        require(value.isNotEmpty())
    }

    override fun toString(): String = value
}

@JvmInline
value class TransactionDataCredentialId(val value: String) : Serializable {
    init {
        require(value.isNotEmpty())
    }

    override fun toString(): String = value
}
