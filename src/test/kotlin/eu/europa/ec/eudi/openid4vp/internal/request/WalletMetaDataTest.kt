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
package eu.europa.ec.eudi.openid4vp.internal.request

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import eu.europa.ec.eudi.openid4vp.*
import eu.europa.ec.eudi.openid4vp.internal.ephemeralJwkSet
import eu.europa.ec.eudi.openid4vp.internal.jsonSupport
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import kotlin.test.*

class WalletMetaDataTest {

    @Test
    fun `test with jar encryption`() {
        val config = SiopOpenId4VPConfig(
            supportedClientIdSchemes = listOf(SupportedClientIdScheme.X509SanDns.NoValidation),
            vpConfiguration = VPConfiguration(
                presentationDefinitionUriSupported = false,
                knownPresentationDefinitionsPerScope = emptyMap(),
                vpFormats = VpFormats(
                    VpFormat.SdJwtVc.ES256,
                    VpFormat.MsoMdoc.ES256,
                ),
            ),
            jarConfiguration = JarConfiguration.Default,
        )
        assertMetadata(config)
    }

    @Test
    fun `test without jar encryption`() {
        val config = SiopOpenId4VPConfig(
            supportedClientIdSchemes = listOf(SupportedClientIdScheme.X509SanDns.NoValidation),
            vpConfiguration = VPConfiguration(
                presentationDefinitionUriSupported = false,
                knownPresentationDefinitionsPerScope = emptyMap(),
                vpFormats = VpFormats(
                    VpFormat.SdJwtVc.ES256,
                    VpFormat.MsoMdoc.ES256,
                ),
            ),
            jarConfiguration = JarConfiguration(
                supportedAlgorithms = JarConfiguration.Default.supportedAlgorithms,
                supportedRequestUriMethods = SupportedRequestUriMethods.Get,
            ),
        )
        assertMetadata(config)
    }
}

private fun assertMetadata(config: SiopOpenId4VPConfig) {
    val (encryptionRequirement, ephemeralJarEncryptionJwks) =
        config.jarConfiguration.supportedRequestUriMethods.isPostSupported()
            ?.let { requestUriMethodPost ->
                when (val jarEncryption = requestUriMethodPost.jarEncryption) {
                    EncryptionRequirement.NotRequired -> jarEncryption to null
                    is EncryptionRequirement.Required -> jarEncryption to jarEncryption.ephemeralJwkSet()
                }
            } ?: (EncryptionRequirement.NotRequired to null)

    val walletMetaData = walletMetaData(config, ephemeralJarEncryptionJwks)
        .also {
            println(jsonSupport.encodeToString(it))
        }

    assertExpectedVpFormats(config.vpConfiguration.vpFormats, walletMetaData)
    assertClientIdScheme(config.supportedClientIdSchemes, walletMetaData)
    assertPresentationDefinitionUriSupported(config.vpConfiguration, walletMetaData)
    assertJarSigning(config.jarConfiguration.supportedAlgorithms, walletMetaData)
    assertJarEncryption(encryptionRequirement, ephemeralJarEncryptionJwks, walletMetaData)
    assertResponseTypes(walletMetaData)
}

private fun assertJarSigning(supportedAlgorithms: List<JWSAlgorithm>, walletMetaData: JsonObject) {
    val algs = walletMetaData["request_object_signing_alg_values_supported"]
    assertIs<JsonArray>(algs)
    assertContentEquals(
        supportedAlgorithms.map { it.name },
        algs.mapNotNull { it.jsonPrimitive.contentOrNull },
    )
}

private fun assertJarEncryption(
    encryptionRequirement: EncryptionRequirement,
    ephemeralJarEncryptionJwks: JWKSet?,
    walletMetadata: JsonObject,
) {
    when (encryptionRequirement) {
        EncryptionRequirement.NotRequired -> {
            assertNull(ephemeralJarEncryptionJwks)
            assertNull(walletMetadata["jwks"])
            assertNull(walletMetadata["authorization_encryption_alg_values_supported"])
            assertNull(walletMetadata["authorization_encryption_enc_values_supported"])
        }

        is EncryptionRequirement.Required -> {
            assertNotNull(ephemeralJarEncryptionJwks)

            val jwks = assertIs<JsonObject>(walletMetadata["jwks"]).let { JWKSet.parse(jsonSupport.encodeToString(it)) }
            assertEquals(ephemeralJarEncryptionJwks.toPublicJWKSet(), jwks)

            val encryptionAlgorithms = assertIs<JsonArray>(walletMetadata["authorization_encryption_alg_values_supported"]).map {
                JWEAlgorithm.parse(it.jsonPrimitive.content)
            }
            assertEquals(encryptionRequirement.supportedEncryptionAlgorithms, encryptionAlgorithms)

            val encryptionMethods = assertIs<JsonArray>(walletMetadata["authorization_encryption_enc_values_supported"]).map {
                EncryptionMethod.parse(it.jsonPrimitive.content)
            }
            assertEquals(encryptionRequirement.supportedEncryptionMethods, encryptionMethods)
        }
    }
}

private fun assertPresentationDefinitionUriSupported(vpConfiguration: VPConfiguration, walletMetaData: JsonObject) {
    val value = walletMetaData["presentation_definition_uri_supported"]
    if (vpConfiguration.presentationDefinitionUriSupported) {
        assertIs<JsonPrimitive>(value)
        assertTrue { value.boolean }
    } else {
        assertTrue {
            value == null || (value is JsonPrimitive && !value.boolean)
        }
    }
}

private fun assertClientIdScheme(
    supportedClientIdSchemes: List<SupportedClientIdScheme>,
    walletMetaData: JsonObject,
) {
    val schemes = walletMetaData["client_id_schemes_supported"]
    if (supportedClientIdSchemes.isNotEmpty()) {
        assertIs<JsonArray>(schemes)
        assertContentEquals(
            supportedClientIdSchemes.map { it.scheme().value() },
            schemes.mapNotNull { it.jsonPrimitive.contentOrNull },
        )
    } else {
        assertNull(schemes)
    }
}

private fun assertExpectedVpFormats(
    expectedVpFormats: VpFormats,
    walletMetaData: JsonObject,
) {
    val vpFormats = assertIs<JsonObject>(
        walletMetaData["vp_formats_supported"],
        "Missing vp_formats_supported",
    )
    if (expectedVpFormats.msoMdoc != null) {
        val msoMdoc = assertNotNull(vpFormats["mso_mdoc"])
        assertIs<JsonObject>(msoMdoc)
        assertTrue { msoMdoc.isNotEmpty() }
    }
    val sdJwtVcSupport = expectedVpFormats.sdJwtVc
    if (sdJwtVcSupport != null) {
        val sdJwtVc = assertNotNull(vpFormats["vc+sd-jwt"])
        assertIs<JsonObject>(sdJwtVc)
        val sdJwtAlgs = sdJwtVc["sd-jwt_alg_values"]
        if (sdJwtVcSupport.sdJwtAlgorithms.isNotEmpty()) {
            assertNotNull(sdJwtAlgs)
            assertIs<JsonArray>(sdJwtAlgs)
            assertContentEquals(
                sdJwtVcSupport.sdJwtAlgorithms.map { it.name },
                sdJwtAlgs.map { it.jsonPrimitive.content },
            )
        } else {
            assertNull(sdJwtAlgs)
        }

        val kbJwtAlgs = sdJwtVc["kb-jwt_alg_values"]
        if (sdJwtVcSupport.kbJwtAlgorithms.isNotEmpty()) {
            assertNotNull(kbJwtAlgs)
            assertIs<JsonArray>(kbJwtAlgs)
            assertContentEquals(
                sdJwtVcSupport.kbJwtAlgorithms.map { it.name },
                kbJwtAlgs.map { it.jsonPrimitive.content },
            )
        } else {
            assertNull(kbJwtAlgs)
        }
    }
}

private fun assertResponseTypes(walletMetadata: JsonObject) {
    val types = assertIs<JsonArray>(walletMetadata["response_types_supported"], "'response_types_supported' is not a json array")
    assert(types.all { it is JsonPrimitive && it.isString }) { "'response_types_supported' does not contain strings only" }

    val values = types.map { it.jsonPrimitive.content }
    assertEquals(3, values.size, "'unexpected number of 'response_types_supported'")
    assert("vp_token" in values) { "'response_types_supported' misses 'vp_token'" }
    assert("id_token" in values) { "'response_types_supported' misses 'id_token'" }
    assert("vp_token id_token" in values) { "'response_types_supported' misses 'vp_token id_token'" }
}
