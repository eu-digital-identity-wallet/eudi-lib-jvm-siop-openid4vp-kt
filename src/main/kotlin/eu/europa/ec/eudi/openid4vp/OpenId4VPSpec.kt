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
}