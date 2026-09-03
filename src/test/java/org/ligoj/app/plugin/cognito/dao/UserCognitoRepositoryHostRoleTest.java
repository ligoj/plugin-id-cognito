/*
 * Licensed under MIT (https://github.com/ligoj/ligoj/blob/master/LICENSE)
 */
package org.ligoj.app.plugin.cognito.dao;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.ligoj.app.plugin.cognito.auth.HostRoleCredentials;
import org.ligoj.app.plugin.cognito.auth.HostRoleCredentialsProvider;
import org.mockito.Mockito;

/**
 * Test class of {@link UserCognitoRepository} host-role credentials fallback.
 */
class UserCognitoRepositoryHostRoleTest {

	private UserCognitoRepository repository;

	private HostRoleCredentialsProvider provider;

	@BeforeEach
	void prepareRepository() {
		repository = new UserCognitoRepository();
		repository.setRegion("eu-west-1");
		repository.setUrl("https://cognito-idp.eu-west-1.amazonaws.com");
		repository.setPoolId("eu-west-1_ABC12345");
		provider = Mockito.mock(HostRoleCredentialsProvider.class);
		repository.setHostRoleCredentialsProvider(provider);
	}

	@Test
	void newRequestHostRole() {
		// Blank static credentials: the host-provided role is used, session token signed along
		repository.setAccessKey(null);
		repository.setSecretKey(null);
		Mockito.when(provider.getCredentials())
				.thenReturn(new HostRoleCredentials("AKIATMP", "secret-tmp", "session-token", "2099-01-01T00:00:00Z"));

		final var request = repository.newRequest("ListUsers", "{}");
		Assertions.assertEquals("session-token", request.getHeaders().get("x-amz-security-token"));
		Assertions.assertTrue(request.getHeaders().get("Authorization").contains("Credential=AKIATMP/"));
		Assertions.assertTrue(request.getHeaders().get("Authorization").contains("x-amz-security-token"));
	}

	@Test
	void newRequestStaticCredentials() {
		// Both static keys provided: the host provider is never consulted
		repository.setAccessKey("AKIASTATIC");
		repository.setSecretKey("static-secret");

		final var request = repository.newRequest("ListUsers", "{}");
		Assertions.assertNull(request.getHeaders().get("x-amz-security-token"));
		Assertions.assertTrue(request.getHeaders().get("Authorization").contains("Credential=AKIASTATIC/"));
		Mockito.verifyNoInteractions(provider);
	}

	@Test
	void newRequestPartialCredentials() {
		// One blank key is enough to fall back to the host-provided role
		repository.setAccessKey("AKIASTATIC");
		repository.setSecretKey(" ");
		Mockito.when(provider.getCredentials())
				.thenReturn(new HostRoleCredentials("AKIATMP", "secret-tmp", "session-token", "2099-01-01T00:00:00Z"));

		final var request = repository.newRequest("ListUsers", "{}");
		Assertions.assertTrue(request.getHeaders().get("Authorization").contains("Credential=AKIATMP/"));
	}
}
