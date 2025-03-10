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

object OpenId4VPSpec {

    const val RESPONSE_URI = "response_uri"
    const val PRESENTATION_DEFINITION = "presentation_definition"
    const val PRESENTATION_DEFINITION_URI = "presentation_definition_uri"
    const val DCQL_QUERY = "dcql_query"

    const val CLIENT_ID_SCHEME_SEPARATOR = ':'
    const val CLIENT_ID_SCHEME_PRE_REGISTERED = "pre-registered"
    const val CLIENT_ID_SCHEME_REDIRECT_URI = "redirect_uri"
    const val CLIENT_ID_SCHEME_HTTPS = "https"
    const val CLIENT_ID_SCHEME_DID = "did"
    const val CLIENT_ID_SCHEME_X509_SAN_URI = "x509_san_uri"
    const val CLIENT_ID_SCHEME_X509_SAN_DNS = "x509_san_dns"
    const val CLIENT_ID_SCHEME_VERIFIER_ATTESTATION = "verifier_attestation"

    const val AUTHORIZATION_REQUEST_OBJECT_TYPE = "oauth-authz-req+jwt"

    const val RM_DIRECT_POST: String = "direct_post"
    const val RM_DIRECT_POST_JWT: String = "direct_post.jwt"

    const val VP_TOKEN: String = "vp_token"

    const val WALLET_NONCE: String = "wallet_nonce"
    const val WALLET_METADATA: String = "wallet_metadata"

    const val FORMAT_MSO_MDOC: String = "mso_mdoc"
    const val FORMAT_SD_JWT_VC: String = "dc+sd-jwt"
    const val FORMAT_W3C_SIGNED_JWT: String = "jwt_vc_json"

    const val DCQL_CREDENTIALS: String = "credentials"
    const val DCQL_CREDENTIAL_SETS: String = "credential_sets"

    const val DCQL_ID: String = "id"
    const val DCQL_FORMAT: String = "format"
    const val DCQL_META: String = "meta"
    const val DCQL_CLAIMS: String = "claims"
    const val DCQL_CLAIM_SETS: String = "claim_sets"
    const val DCQL_OPTIONS: String = "options"
    const val DCQL_REQUIRED: String = "required"
    const val DCQL_PURPOSE: String = "purpose"
    const val DCQL_PATH: String = "path"
    const val DCQL_VALUES: String = "values"
    const val DCQL_SD_JWT_VC_VCT_VALUES: String = "vct_values"
    const val DCQL_MSO_MDOC_DOCTYPE_VALUE: String = "doctype_value"
    const val DCQL_MSO_MDOC_NAMESPACE: String = "namespace"
    const val DCQL_MSO_MDOC_CLAIM_NAME: String = "claim_name"

    const val TRANSACTION_DATA: String = "transaction_data"
    const val TRANSACTION_DATA_TYPE: String = "type"
    const val TRANSACTION_DATA_CREDENTIAL_IDS: String = "credential_ids"
    const val TRANSACTION_DATA_HASH_ALGORITHMS: String = "transaction_data_hashes_alg"
}

object SIOPv2
