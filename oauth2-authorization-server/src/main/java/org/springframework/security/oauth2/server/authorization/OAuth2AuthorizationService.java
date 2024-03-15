/*
 * Copyright 2020-2022 the original author or authors.
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

/**
 * Implementations of this interface are responsible for the management
 * of {@link OAuth2Authorization OAuth 2.0 Authorization(s)}.
 *
 * OAuth2AuthorizationService 是存储新授权和查询现有授权的中心组件。其他组件在遵循特定协议流程（如客户端身份验证、授权授予处理、
 * 令牌反省、令牌撤销、动态客户端注册等）时都会用到它。
 *
 * OAuth2AuthorizationService 的实现有 InMemoryOAuth2AuthorizationService 和 JdbcOAuth2AuthorizationService。
 * InMemoryOAuth2AuthorizationService 实现在内存中存储 OAuth2Authorization 实例，建议仅在开发和测试期间使用。
 * JdbcOAuth2AuthorizationService 是一种 JDBC 实现，它通过使用 JdbcOperations 来持久化 OAuth2Authorization 实例。
 *
 * @author Joe Grandja
 * @since 0.0.1
 * @see OAuth2Authorization
 * @see OAuth2TokenType
 */
public interface OAuth2AuthorizationService {

	/**
	 * Saves the {@link OAuth2Authorization}.
	 *
	 * @param authorization the {@link OAuth2Authorization}
	 */
	void save(OAuth2Authorization authorization);

	/**
	 * Removes the {@link OAuth2Authorization}.
	 *
	 * @param authorization the {@link OAuth2Authorization}
	 */
	void remove(OAuth2Authorization authorization);

	/**
	 * Returns the {@link OAuth2Authorization} identified by the provided {@code id},
	 * or {@code null} if not found.
	 *
	 * @param id the authorization identifier
	 * @return the {@link OAuth2Authorization} if found, otherwise {@code null}
	 */
	@Nullable
	OAuth2Authorization findById(String id);

	/**
	 * Returns the {@link OAuth2Authorization} containing the provided {@code token},
	 * or {@code null} if not found.
	 *
	 * @param token the token credential
	 * @param tokenType the {@link OAuth2TokenType token type}
	 * @return the {@link OAuth2Authorization} if found, otherwise {@code null}
	 */
	@Nullable
	OAuth2Authorization findByToken(String token, @Nullable OAuth2TokenType tokenType);

}
