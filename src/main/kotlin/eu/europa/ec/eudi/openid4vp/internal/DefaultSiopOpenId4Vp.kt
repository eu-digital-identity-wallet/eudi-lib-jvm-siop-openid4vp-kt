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

import eu.europa.ec.eudi.openid4vp.AuthorizationRequestResolver
import eu.europa.ec.eudi.openid4vp.AuthorizationResponseBuilder
import eu.europa.ec.eudi.openid4vp.Dispatcher
import eu.europa.ec.eudi.openid4vp.SiopOpenId4Vp

/**
 * An implementation of [SiopOpenId4Vp].
 *
 */
internal class DefaultSiopOpenId4Vp(
    private val authorizationResolver: AuthorizationRequestResolver,
    private val dispatcher: Dispatcher,
    private val authorizationResponseBuilder: AuthorizationResponseBuilder,
) : SiopOpenId4Vp,
    AuthorizationRequestResolver by authorizationResolver,
    Dispatcher by dispatcher,
    AuthorizationResponseBuilder by authorizationResponseBuilder
