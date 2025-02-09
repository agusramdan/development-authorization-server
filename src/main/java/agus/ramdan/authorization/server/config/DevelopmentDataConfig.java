/*
 * Copyright 2025-2025 the original author or authors.
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
package agus.ramdan.authorization.server.config;

import lombok.val;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import java.util.ArrayList;
import java.util.UUID;

@Configuration(proxyBeanMethods = false)
public class DevelopmentDataConfig {

	// @formatter:off
	@Bean
	public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
		val list = new ArrayList<RegisteredClient>();
		// Save registered client in db as if in-memory
		list.add(RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("messaging-client")
				.clientSecret("{noop}secret")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
				.redirectUri("http://127.0.0.1:8080/authorized")
				.scope(OidcScopes.OPENID)
				.scope(OidcScopes.PROFILE)
				.scope("message.read")
				.scope("message.write")
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
				.build());
		//registeredClientRepository.save(registeredClient);

		list.add(RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("client")
				.clientSecret("{noop}secret2")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
				.redirectUri("http://127.0.0.1:8080/authorized")
				.scope(OidcScopes.OPENID)
				.scope(OidcScopes.PROFILE)
				.scope("read")
				.scope("write")
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
				.build());
		list.add(RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("client-web")
				.clientSecret("{noop}secret3")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
				.redirectUri("http://127.0.0.1:8080/authorized")
				.scope(OidcScopes.OPENID)
				.scope(OidcScopes.PROFILE)
				.scope("read")
				.scope("write")
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
				.build());

		list.add(RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("client-internal-web")
				.clientSecret("{noop}secret4")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
				.redirectUri("http://127.0.0.1:8080/authorized")
				.scope(OidcScopes.OPENID)
				.scope(OidcScopes.PROFILE)
				.scope("read")
				.scope("write")
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
				.build());

		list.add(RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("client-external-web")
				.clientSecret("{noop}secret5")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
				.redirectUri("http://127.0.0.1:8080/authorized")
				.scope(OidcScopes.OPENID)
				.scope(OidcScopes.PROFILE)
				.scope("read")
				.scope("write")
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
				.build());

		list.add(RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("client-mobile")
				.clientSecret("{noop}secret6")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
				.redirectUri("http://127.0.0.1:8080/authorized")
				.scope(OidcScopes.OPENID)
				.scope(OidcScopes.PROFILE)
				.scope("read")
				.scope("write")
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
				.build());
		list.add(RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("client-customer-mobile")
				.clientSecret("{noop}secret7")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
				.redirectUri("http://127.0.0.1:8080/authorized")
				.scope(OidcScopes.OPENID)
				.scope(OidcScopes.PROFILE)
				.scope("customer.read")
				.scope("customer.write")
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
				.build());

		list.add(RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("client-supplier-mobile")
				.clientSecret("{noop}secret8")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
				.redirectUri("http://127.0.0.1:8080/authorized")
				.scope(OidcScopes.OPENID)
				.scope(OidcScopes.PROFILE)
				.scope("supplier.read")
				.scope("supplier.write")
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
				.build());
		list.add(RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("client-cdm")
				.clientSecret("{noop}secret9")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
				.redirectUri("http://127.0.0.1:8080/authorized")
				.scope("cdm.read")
				.scope("cdm.write")
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
				.build());
		list.add(RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("client-odoo")
				.clientSecret("{noop}secret10")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
				.redirectUri("http://127.0.0.1:8080/authorized")
				.scope("odoo.read")
				.scope("odoo.write")
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
				.build());
		JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
		list.forEach(registeredClientRepository::save);
		return registeredClientRepository;
	}
	// @formatter:on
	// @formatter:off
	@Bean
	public UserDetailsService users(JdbcTemplate jdbcTemplate) {
		val list = new ArrayList<UserDetails>();
		list.add(User.withDefaultPasswordEncoder()
				.username("user1")
				.password("password")
				.roles("USER")
				.build());
		list.add(User.withDefaultPasswordEncoder()
				.username("sa")
				.password("password")
				.roles("SYSTEM_ADMIN")
				.build());
		list.add(User.withDefaultPasswordEncoder()
				.username("admin")
				.password("password")
				.roles("INTERNAL_ADMIN")
				.build());
		list.add(User.withDefaultPasswordEncoder()
				.username("user")
				.password("password")
				.roles("INTERNAL_USER")
				.build());
		list.add(User.withDefaultPasswordEncoder()
				.username("admin_customer")
				.password("password")
				.roles("ADMIN_CUSTOMER")
				.build());
		list.add(User.withDefaultPasswordEncoder()
				.username("user_customer")
				.password("password")
				.roles("USER_CUSTOMER")
				.build());
		list.add(User.withDefaultPasswordEncoder()
				.username("admin_supplier")
				.password("password")
				.roles("ADMIN_SUPPLIER")
				.build());
		list.add(User.withDefaultPasswordEncoder()
				.username("user_supplier")
				.password("password")
				.roles("USER_SUPPLIER")
				.build());
//		val usersJdbcDao = new JdbcDaoImpl();
//		usersJdbcDao.setJdbcTemplate(jdbcTemplate);
//		usersJdbcDao.setRolePrefix("ROLE_");
		return new InMemoryUserDetailsManager(list);
	}
	// @formatter:on

	@Bean
	public EmbeddedDatabase embeddedDatabase() {
		// @formatter:off
		return new EmbeddedDatabaseBuilder()
				.generateUniqueName(true)
				.setType(EmbeddedDatabaseType.H2)
				.setScriptEncoding("UTF-8")
				.addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql")
				.addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql")
				.addScript("org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql")
				.build();
		// @formatter:on
	}
}
