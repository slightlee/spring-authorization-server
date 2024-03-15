/*
 * Copyright 2020-2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.server.authorization;

import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.security.Principal;

/**
 * Implementations of this interface are responsible for the management
 * of {@link OAuth2AuthorizationConsent OAuth 2.0 Authorization Consent(s)}.
 *
 * OAuth2AuthorizationConsentService 是存储新授权同意和查询现有授权同意的中心组件。
 * 它主要由实现 OAuth2 授权请求流程（例如授权代码授予）的组件使用。
 *
 * OAuth2AuthorizationConsentService 的实现有 InMemoryOAuth2AuthorizationConsentService 和
 * JdbcOAuth2AuthorizationConsentService。InMemoryOAuth2AuthorizationConsentService 实现在内存中存储
 * OAuth2AuthorizationConsent 实例，建议仅用于开发和测试。JdbcOAuth2AuthorizationConsentService 是一种 JDBC 实现，
 * 它通过使用 JdbcOperations 来持久化 OAuth2AuthorizationConsent 实例。
 *
 * ！！！可选组件！！！
 *
 * @author Daniel Garnier-Moiroux
 * @since 0.1.2
 * @see OAuth2AuthorizationConsent
 */
public interface OAuth2AuthorizationConsentService {

	/**
	 * Saves the {@link OAuth2AuthorizationConsent}.
	 *
	 * @param authorizationConsent the {@link OAuth2AuthorizationConsent}
	 */
	void save(OAuth2AuthorizationConsent authorizationConsent);

	/**
	 * Removes the {@link OAuth2AuthorizationConsent}.
	 *
	 * @param authorizationConsent the {@link OAuth2AuthorizationConsent}
	 */
	void remove(OAuth2AuthorizationConsent authorizationConsent);

	/**
	 * Returns the {@link OAuth2AuthorizationConsent} identified by the provided
	 * {@code registeredClientId} and {@code principalName}, or {@code null} if not found.
	 *
	 * @param registeredClientId the identifier for the {@link RegisteredClient}
	 * @param principalName the name of the {@link Principal}
	 * @return the {@link OAuth2AuthorizationConsent} if found, otherwise {@code null}
	 */
	@Nullable
	OAuth2AuthorizationConsent findById(String registeredClientId, String principalName);

}
