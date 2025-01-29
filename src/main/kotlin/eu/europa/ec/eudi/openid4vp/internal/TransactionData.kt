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

import com.nimbusds.jose.util.Base64URL
import eu.europa.ec.eudi.openid4vp.OpenId4VPSpec
import eu.europa.ec.eudi.openid4vp.TransactionData
import kotlinx.io.bytestring.decodeToByteString
import kotlinx.io.bytestring.decodeToString
import kotlinx.serialization.json.*

/**
 * Smart constructor for [TransactionData].
 */
internal fun TransactionData(encoded: String): Result<TransactionData> = runCatching {
    val decoded = base64UrlNoPadding.decodeToByteString(encoded)
    val serialized = decoded.decodeToString()
    val deserialized = jsonSupport.decodeFromString<JsonObject>(serialized)

    deserialized.requiredString(OpenId4VPSpec.TRANSACTION_DATA_TYPE)
    deserialized.requiredStringArray(OpenId4VPSpec.TRANSACTION_DATA_CREDENTIAL_IDS)
    deserialized.optionalStringArray(OpenId4VPSpec.TRANSACTION_DATA_HASH_ALGORITHMS)

    TransactionData(encoded = Base64URL.from(encoded), deserialized = deserialized)
}
