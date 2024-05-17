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

import java.net.URI

@JvmInline
internal value class AbsoluteDIDUrl private constructor(val uri: URI) {

    override fun toString(): String = uri.toString()

    companion object {
        fun parse(s: String): Result<AbsoluteDIDUrl> = runCatching {
            val uri = URI.create(s)
            uri.ensureScheme()
            uri.ensureIsAbsolute()
            val (_, method, _) = s.split(":", limit = 3)
            require(method.isNotEmpty())
            require(!uri.query.isNullOrEmpty() || !uri.path.isNullOrBlank() || !uri.fragment.isNullOrBlank())
            AbsoluteDIDUrl(uri)
        }
    }
}

@JvmInline
internal value class DID private constructor(val uri: URI) {

    override fun toString(): String = uri.toString()

    companion object {
        fun parse(s: String): Result<DID> = runCatching {
            val uri = URI.create(s)
            uri.ensureScheme()
            uri.ensureIsAbsolute()
            require(uri.path.isNullOrEmpty())
            require(uri.fragment.isNullOrEmpty())
            require(uri.query.isNullOrEmpty())
            val (_, method, identifier) = s.split(":", limit = 3)
            require(method.isNotEmpty())
            require(identifier.isNotEmpty())
            DID(uri)
        }
    }
}

private fun URI.ensureScheme() = require(scheme == "did") { "Scheme should be did" }
private fun URI.ensureIsAbsolute() = require(isAbsolute)
