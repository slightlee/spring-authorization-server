/*
 * Copyright 2020-2023 the original author or authors.
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

import java.io.Serializable;
import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;

import org.springframework.lang.NonNull;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.util.SpringAuthorizationServerVersion;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

/**
 * A representation of an OAuth 2.0 "consent" to an Authorization request, which holds state related to the
 * set of {@link #getAuthorities() authorities} granted to a {@link #getRegisteredClientId() client} by the
 * {@link #getPrincipalName() resource owner}.
 * <p>
 * When authorizing access for a given client, the resource owner may only grant a subset of the authorities
 * the client requested. The typical use-case is the {@code authorization_code} flow, in which the client
 * requests a set of {@code scope}s. The resource owner then selects which scopes they grant to the client.
 *
 * OAuth2AuthorizationConsent 是来自 OAuth2 授权请求流的授权 "同意"（决定）的表示--例如，authorization_code grant（授权码授予），
 * 它包含资源所有者授予客户端的权限。
 *
 * 在授权客户访问时，资源所有者可能只授予客户请求的授权的一个子集。典型的用例是授权_代码授予流，其中客户请求范围，
 * 资源所有者授予（或拒绝）对所请求范围的访问。
 *
 * @author Daniel Garnier-Moiroux
 * @since 0.1.2
 */
public final class OAuth2AuthorizationConsent implements Serializable {
	private static final long serialVersionUID = SpringAuthorizationServerVersion.SERIAL_VERSION_UID;
	private static final String AUTHORITIES_SCOPE_PREFIX = "SCOPE_";

	private final String registeredClientId;
	private final String principalName;  // 资源所有者的主体名称。
	private final Set<GrantedAuthority> authorities; //  资源所有者授予客户端的权限。授权可以代表范围、权利要求、权限、角色等。

	private OAuth2AuthorizationConsent(String registeredClientId, String principalName, Set<GrantedAuthority> authorities) {
		this.registeredClientId = registeredClientId;
		this.principalName = principalName;
		this.authorities = Collections.unmodifiableSet(authorities);
	}

	/**
	 * Returns the identifier for the {@link RegisteredClient#getId() registered client}.
	 *
	 * @return the {@link RegisteredClient#getId()}
	 */
	public String getRegisteredClientId() {
		return this.registeredClientId;
	}

	/**
	 * Returns the {@code Principal} name of the resource owner (or client).
	 *
	 * @return the {@code Principal} name of the resource owner (or client)
	 */
	public String getPrincipalName() {
		return this.principalName;
	}

	/**
	 * Returns the {@link GrantedAuthority authorities} granted to the client by the principal.
	 *
	 * @return the {@link GrantedAuthority authorities} granted to the client by the principal.
	 */
	public Set<GrantedAuthority> getAuthorities() {
		return this.authorities;
	}

	/**
	 * Convenience method for obtaining the {@code scope}s granted to the client by the principal,
	 * extracted from the {@link #getAuthorities() authorities}.
	 *
	 * @return the {@code scope}s granted to the client by the principal.
	 */
	public Set<String> getScopes() {
		Set<String> authorities = new HashSet<>();
		for (GrantedAuthority authority : getAuthorities()) {
			if (authority.getAuthority().startsWith(AUTHORITIES_SCOPE_PREFIX)) {
				authorities.add(authority.getAuthority().substring(AUTHORITIES_SCOPE_PREFIX.length()));
			}
		}
		return authorities;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null || getClass() != obj.getClass()) {
			return false;
		}
		OAuth2AuthorizationConsent that = (OAuth2AuthorizationConsent) obj;
		return Objects.equals(this.registeredClientId, that.registeredClientId) &&
				Objects.equals(this.principalName, that.principalName) &&
				Objects.equals(this.authorities, that.authorities);
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.registeredClientId, this.principalName, this.authorities);
	}

	/**
	 * Returns a new {@link Builder}, initialized with the values from the provided {@code OAuth2AuthorizationConsent}.
	 *
	 * @param authorizationConsent the {@code OAuth2AuthorizationConsent} used for initializing the {@link Builder}
	 * @return the {@link Builder}
	 */
	public static Builder from(OAuth2AuthorizationConsent authorizationConsent) {
		Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");
		return new Builder(
				authorizationConsent.getRegisteredClientId(),
				authorizationConsent.getPrincipalName(),
				authorizationConsent.getAuthorities()
		);
	}

	/**
	 * Returns a new {@link Builder}, initialized with the given {@link RegisteredClient#getClientId() registeredClientId}
	 * and {@code Principal} name.
	 *
	 * @param registeredClientId the {@link RegisteredClient#getId()}
	 * @param principalName the  {@code Principal} name
	 * @return the {@link Builder}
	 */
	public static Builder withId(@NonNull String registeredClientId, @NonNull String principalName) {
		Assert.hasText(registeredClientId, "registeredClientId cannot be empty");
		Assert.hasText(principalName, "principalName cannot be empty");
		return new Builder(registeredClientId, principalName);
	}


	/**
	 * A builder for {@link OAuth2AuthorizationConsent}.
	 */
	public static final class Builder implements Serializable {
		private static final long serialVersionUID = SpringAuthorizationServerVersion.SERIAL_VERSION_UID;

		private final String registeredClientId;
		private final String principalName;
		private final Set<GrantedAuthority> authorities = new HashSet<>();

		private Builder(String registeredClientId, String principalName) {
			this(registeredClientId, principalName, Collections.emptySet());
		}

		private Builder(String registeredClientId, String principalName, Set<GrantedAuthority> authorities) {
			this.registeredClientId = registeredClientId;
			this.principalName = principalName;
			if (!CollectionUtils.isEmpty(authorities)) {
				this.authorities.addAll(authorities);
			}
		}

		/**
		 * Adds a scope to the collection of {@code authorities} in the resulting {@link OAuth2AuthorizationConsent},
		 * wrapping it in a {@link SimpleGrantedAuthority}, prefixed by {@code SCOPE_}. For example, a
		 * {@code message.write} scope would be stored as {@code SCOPE_message.write}.
		 *
		 * @param scope the scope
		 * @return the {@code Builder} for further configuration
		 */
		public Builder scope(String scope) {
			authority(new SimpleGrantedAuthority(AUTHORITIES_SCOPE_PREFIX + scope));
			return this;
		}

		/**
		 * Adds a {@link GrantedAuthority} to the collection of {@code authorities} in the
		 * resulting {@link OAuth2AuthorizationConsent}.
		 *
		 * @param authority the {@link GrantedAuthority}
		 * @return the {@code Builder} for further configuration
		 */
		public Builder authority(GrantedAuthority authority) {
			this.authorities.add(authority);
			return this;
		}

		/**
		 * A {@code Consumer} of the {@code authorities}, allowing the ability to add, replace or remove.
		 *
		 * @param authoritiesConsumer a {@code Consumer} of the {@code authorities}
		 * @return the {@code Builder} for further configuration
		 */
		public Builder authorities(Consumer<Set<GrantedAuthority>> authoritiesConsumer) {
			authoritiesConsumer.accept(this.authorities);
			return this;
		}

		/**
		 * Validate the authorities and build the {@link OAuth2AuthorizationConsent}.
		 * There must be at least one {@link GrantedAuthority}.
		 *
		 * @return the {@link OAuth2AuthorizationConsent}
		 */
		public OAuth2AuthorizationConsent build() {
			Assert.notEmpty(this.authorities, "authorities cannot be empty");
			return new OAuth2AuthorizationConsent(this.registeredClientId, this.principalName, this.authorities);
		}
	}
}
