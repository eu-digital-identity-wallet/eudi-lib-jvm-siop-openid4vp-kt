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

    const val CLIENT_ID_SCHEME_SEPARATOR = ':'
    const val CLIENT_ID_SCHEME_PRE_REGISTERED = "pre-registered"
    const val CLIENT_ID_SCHEME_REDIRECT_URI = "redirect_uri"
    const val CLIENT_ID_SCHEME_HTTPS = "https"
    const val CLIENT_ID_SCHEME_DID = "did"
    const val CLIENT_ID_SCHEME_X509_SAN_URI = "x509_san_uri"
    const val CLIENT_ID_SCHEME_X509_SAN_DNS = "x509_san_dns"
    const val CLIENT_ID_SCHEME_VERIFIER_ATTESTATION = "verifier_attestation"

    public const val RM_DIRECT_POST: String = "direct_post"
    public const val RM_DIRECT_POST_JWT: String = "direct_post.jwt"

    public const val VP_TOKEN: String = "vp_token"

    public const val WALLET_NONCE: String = "wallet_nonce"
    public const val WALLET_METADATA: String = "wallet_metadata"

    public const val FORMAT_MSO_MDOC: String = "mso_mdoc"

    @Deprecated(
        message = "Removed by spec",
    )
    public const val FORMAT_SD_JWT_VC_DEPRECATED: String = "vc+sd-jwt"
    public const val FORMAT_SD_JWT_VC: String = "dc+sd-jwt"
    public const val FORMAT_W3C_SIGNED_JWT: String = "jwt_vc_json"

    public const val DCQL_CREDENTIALS: String = "credentials"
    public const val DCQL_CREDENTIAL_SETS: String = "credential_sets"

    public const val DCQL_ID: String = "id"
    public const val DCQL_FORMAT: String = "format"
    public const val DCQL_META: String = "meta"
    public const val DCQL_CLAIMS: String = "claims"
    public const val DCQL_CLAIM_SETS: String = "claim_sets"
    public const val DCQL_OPTIONS: String = "options"
    public const val DCQL_REQUIRED: String = "required"
    public const val DCQL_PURPOSE: String = "purpose"
    public const val DCQL_PATH: String = "path"
    public const val DCQL_VALUES: String = "values"
    public const val DCQL_SD_JWT_VC_VCT_VALUES: String = "vct_values"
    public const val DCQL_MSO_MDOC_DOCTYPE_VALUE: String = "doctype_value"
    public const val DCQL_MSO_MDOC_NAMESPACE: String = "namespace"
    public const val DCQL_MSO_MDOC_CLAIM_NAME: String = "claim_name"
}

public object SIOPv2
