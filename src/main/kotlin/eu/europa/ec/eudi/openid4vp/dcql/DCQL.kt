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
package eu.europa.ec.eudi.openid4vp.dcql

import eu.europa.ec.eudi.openid4vp.Format
import eu.europa.ec.eudi.openid4vp.OpenId4VPSpec
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject

typealias Credentials = List<CredentialQuery>
typealias CredentialSets = List<CredentialSetQuery>
typealias CredentialSet = Set<QueryId>
typealias ClaimSet = Set<ClaimId>

@Serializable
data class DCQL(
    /**
     * A non-empty list of [Credential Queries][CredentialQuery], that specify the requested Verifiable Credentials
     */
    @SerialName(OpenId4VPSpec.DCQL_CREDENTIALS) @Required val credentials: Credentials,
    /**
     * A non-empty list of [credential set queries][CredentialSetQuery], that specifies additional constraints
     * on which of the requested Verifiable Credentials to return
     */
    @SerialName(OpenId4VPSpec.DCQL_CREDENTIAL_SETS) val credentialSets: CredentialSets? = null,

) {
    init {
        val uniqueIds = credentials.ensureValid()
        credentialSets?.apply { ensureValid(uniqueIds) }
    }

    companion object {
        private fun Credentials.ensureValid(): Set<QueryId> {
            require(isNotEmpty()) { "At least one credential must be defined" }
            return ensureUniqueIds()
        }

        private fun Credentials.ensureUniqueIds(): Set<QueryId> {
            val uniqueIds = map { it.id }.toSet()
            require(uniqueIds.size == size) {
                "Within the Authorization Request, the same credential query id MUST NOT be present more than once"
            }
            return uniqueIds
        }

        private fun CredentialSets.ensureValid(queryIds: Set<QueryId>) {
            require(isNotEmpty())
            forEach { credentialSet -> credentialSet.ensureOptionsWithKnownIds(queryIds) }
        }

        private fun CredentialSetQuery.ensureOptionsWithKnownIds(knownIds: Set<QueryId>) {
            options.forEach { credentialSet ->
                require(credentialSet.all { it in knownIds }) { "Unknown credential query ids in option $credentialSet" }
            }
        }
    }
}

/**
 * The [value] must be a non-empty string consisting of alphanumeric, underscore (_) or hyphen (-) characters
 */
@Serializable
@JvmInline
value class QueryId(val value: String) {
    init {
        DCQLId.ensureValid(value)
    }

    override fun toString(): String = value
}

/**
 * Represents a request for a presentation of one Credential.
 */
@Serializable
data class CredentialQuery(
    @SerialName(OpenId4VPSpec.DCQL_ID) @Required val id: QueryId,
    @SerialName(OpenId4VPSpec.DCQL_FORMAT) @Required val format: Format,
    /**
     * An object defining additional properties requested by the Verifier that apply
     * to the metadata and validity data of the Credential.
     * The properties of this object are defined per Credential Format.
     * If omitted, no specific constraints are placed on the metadata or validity of the requested Credential.
     *
     * @see [CredentialQuery.metaMsoMdoc]
     */
    @SerialName(OpenId4VPSpec.DCQL_META) val meta: JsonObject? = null,

    /**
     * A non-empty list that specifies claims in the requested Credential.
     */
    @SerialName(OpenId4VPSpec.DCQL_CLAIMS) val claims: List<ClaimsQuery>? = null,

    /**
     *A non-empty set containing sets of identifiers for elements in claims that
     * specifies which combinations of claims for the Credential are requested
     */
    @SerialName(OpenId4VPSpec.DCQL_CLAIM_SETS) val claimSets: List<ClaimSet>? = null,

) {

    init {
        if (claims != null) {
            claims.ensureValid(format)
            claimSets?.ensureValid(claims)
        } else {
            require(claimSets == null) { "Cannot provide ${OpenId4VPSpec.DCQL_CLAIM_SETS} without ${OpenId4VPSpec.DCQL_CLAIMS}" }
        }
    }

    companion object {

        fun sdJwtVc(
            id: QueryId,
            sdJwtVcMeta: DCQLMetaSdJwtVcExtensions? = null,
            claims: List<ClaimsQuery>? = null,
            claimSets: List<ClaimSet>? = null,
        ): CredentialQuery {
            val meta = sdJwtVcMeta?.let { JsonSupport.encodeToJsonElement(it).jsonObject }
            return CredentialQuery(id, Format.SdJwtVc, meta, claims, claimSets)
        }

        fun mdoc(
            id: QueryId,
            msoMdocMeta: DCQLMetaMsoMdocExtensions? = null,
            claims: List<ClaimsQuery>? = null,
            claimSets: List<ClaimSet>? = null,
        ): CredentialQuery {
            val meta = msoMdocMeta?.let { JsonSupport.encodeToJsonElement(it).jsonObject }
            return CredentialQuery(id, Format.MsoMdoc, meta, claims, claimSets)
        }

        private fun List<ClaimsQuery>.ensureValid(format: Format) {
            require(isNotEmpty()) { "At least one claim must be defined" }
            ensureUniqueIds()
            when (format) {
                Format.MsoMdoc -> {
                    forEach { ClaimsQuery.ensureMsoMdocExtensions(it) }
                }
            }
        }

        private fun List<ClaimsQuery>.ensureUniqueIds() {
            val ids = mapNotNull { it.id }
            val uniqueIdsNo = ids.toSet().count()
            require(uniqueIdsNo == ids.size) {
                "Within a CredentialQuery, the same id of claims MUST NOT be present more than once"
            }
        }

        private fun List<ClaimSet>.ensureValid(claims: List<ClaimsQuery>) {
            val claimIds = claims.mapNotNull { it.id }
            require(this.isNotEmpty()) { "${OpenId4VPSpec.DCQL_CLAIM_SETS} cannot be empty" }
            this.forEach { claimSet ->

                require(claimSet.isNotEmpty()) {
                    "Each element of ${OpenId4VPSpec.DCQL_CLAIM_SETS} cannot be empty"
                }
                require(claimSet.all { id -> id in claimIds }) {
                    "Unknown claim ids within $claimSet"
                }
            }
        }
    }
}

val CredentialQuery.metaMsoMdoc: DCQLMetaMsoMdocExtensions? get() = meta.metaAs()
val CredentialQuery.metaSdJwtVc: DCQLMetaSdJwtVcExtensions? get() = meta.metaAs()
internal inline fun <reified T> JsonObject?.metaAs(): T? = this?.let { JsonSupport.decodeFromJsonElement(it) }

@Serializable
data class CredentialSetQuery(

    @SerialName(OpenId4VPSpec.DCQL_OPTIONS) @Required val options: List<CredentialSet>,

    /**
     * A boolean which indicates whether this set of Credentials is required
     * to satisfy the particular use case at the Verifier.
     *
     * If omitted, the default value is true
     */
    @SerialName(OpenId4VPSpec.DCQL_REQUIRED) val required: Boolean? = DefaultRequiredValue,

    /**
     *  A string, number or object specifying the purpose of the query.
     *  [OpenId4VPSpec]  does not define a specific structure or specific values for this property.
     *  The purpose is intended to be used by the Verifier to communicate the reason for the query to the Wallet.
     *  The Wallet MAY use this information to show the user the reason for the request
     */
    @SerialName(OpenId4VPSpec.DCQL_PURPOSE) val purpose: JsonElement? = null,
) {

    init {
        options.forEach { credentialSet ->
            require(credentialSet.isNotEmpty()) { "An credentialSet must have at least one CredentialQueryId" }
        }
    }

    companion object {

        val DefaultRequiredValue: Boolean? = true
    }
}

@Serializable
@JvmInline
value class ClaimId(val value: String) {
    init {
        DCQLId.ensureValid(value)
    }

    override fun toString(): String = value
}

@Serializable
data class ClaimsQuery(
    @SerialName(OpenId4VPSpec.DCQL_ID) val id: ClaimId? = null,
    @SerialName(OpenId4VPSpec.DCQL_PATH) val path: ClaimPath? = null,
    @SerialName(OpenId4VPSpec.DCQL_VALUES) val values: JsonArray? = null,
    @SerialName(OpenId4VPSpec.DCQL_MSO_MDOC_NAMESPACE) override val namespace: MsoMdocNamespace? = null,
    @SerialName(OpenId4VPSpec.DCQL_MSO_MDOC_CLAIM_NAME) override val claimName: MsoMdocClaimName? = null,
) : MsoMdocClaimsQueryExtension {

    companion object {

        fun sdJwtVc(
            id: ClaimId? = null,
            path: ClaimPath? = null,
            values: JsonArray? = null,
        ): ClaimsQuery = ClaimsQuery(id, path, values)

        fun mdoc(
            id: ClaimId? = null,
            values: JsonArray? = null,
            namespace: MsoMdocNamespace,
            claimName: MsoMdocClaimName,
        ): ClaimsQuery = ClaimsQuery(id = id, path = null, values = values, namespace = namespace, claimName = claimName)

        fun ensureMsoMdocExtensions(claimsQuery: ClaimsQuery) {
            requireNotNull(claimsQuery.namespace) {
                "Namespace is required if the credential format is based on the mdoc format "
            }
            requireNotNull(claimsQuery.claimName) {
                "Claim name is required if the credential format is based on the mdoc format "
            }
        }
    }
}

//
// SD-JWT-VC
//

@Serializable
data class DCQLMetaSdJwtVcExtensions(
    /**
     * Specifies allowed values for the type of the requested Verifiable Credential.
     * All elements in the array MUST be valid type identifiers.
     * The Wallet may return credentials that inherit from any of the specified types
     */
    @SerialName(OpenId4VPSpec.DCQL_SD_JWT_VC_VCT_VALUES) val vctValues: List<String>?,
)

//
//
//  MSO_MDOC
//

@Serializable
@JvmInline
value class MsoMdocDocType(val value: String) {
    init {
        require(value.isNotBlank()) { "Doctype cannt be blank" }
    }

    override fun toString(): String = value
}

/**
 * The following is an ISO mdoc specific parameter in the [meta parameter][CredentialQuery.meta]
 */
@Serializable
data class DCQLMetaMsoMdocExtensions(
    /**
     * Specifies an allowed value for the doctype of the requested Verifiable Credential.
     * It MUST be a valid doctype identifier as defined
     */
    @SerialName(OpenId4VPSpec.DCQL_MSO_MDOC_DOCTYPE_VALUE) val doctypeValue: MsoMdocDocType?,
)

@Serializable
@JvmInline
value class MsoMdocNamespace(val value: String) {
    init {
        require(value.isNotBlank()) { "Namespace must not be blank" }
    }

    override fun toString(): String = value
}

@Serializable
@JvmInline
value class MsoMdocClaimName(val value: String) {
    init {
        require(value.isNotBlank()) { "Claim name must not be blank" }
    }

    override fun toString(): String = value
}

/**
 * The following are ISO mdoc specific parameters to be used in a [Claims Query][ClaimsQuery]
 */
interface MsoMdocClaimsQueryExtension {

    /**
     * Required if the Credential Format is based on the mdoc format.
     * Must not be present otherwise.
     * The namespace of the data element within the mdoc
     */
    @SerialName(OpenId4VPSpec.DCQL_MSO_MDOC_NAMESPACE)
    val namespace: MsoMdocNamespace?

    /**
     * REQUIRED if the Credential Format is based on mdoc format
     * Must not be present otherwise.
     * Specifies the data element identifier of the data element
     * within the provided [namespace] in the mdoc
     */
    @SerialName(OpenId4VPSpec.DCQL_MSO_MDOC_CLAIM_NAME)
    val claimName: MsoMdocClaimName?
}

internal object DCQLId {
    const val REGEX: String = "^[a-zA-Z0-9_-]+$"
    fun ensureValid(value: String): String {
        require(value.isNotEmpty()) { "Value cannot be be empty" }
        require(REGEX.toRegex().matches(value)) {
            "The value must be a non-empty string consisting of alphanumeric, underscore (_) or hyphen (-) characters"
        }
        return value
    }
}

private val JsonSupport = Json {
    prettyPrint = false
    ignoreUnknownKeys = true
}