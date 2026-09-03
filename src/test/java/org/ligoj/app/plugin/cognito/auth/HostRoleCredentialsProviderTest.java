/*
 * Licensed under MIT (https://github.com/ligoj/ligoj/blob/master/LICENSE)
 */
package org.ligoj.app.plugin.cognito.auth;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.ligoj.app.AbstractServerTest;
import org.ligoj.bootstrap.core.json.ObjectMapperTrim;
import org.ligoj.bootstrap.resource.system.configuration.ConfigurationResource;
import org.mockito.Mockito;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.nio.file.Files;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.*;

/**
 * Test class of {@link HostRoleCredentialsProvider} and {@link HostRoleCredentials}
 */
class HostRoleCredentialsProviderTest extends AbstractServerTest {

	private static final String MOCK_URL = "http://localhost:" + MOCK_PORT;

	private HostRoleCredentialsProvider provider;

	private final Map<String, String> env = new HashMap<>();

	/**
	 * Valid credentials payload, far expiration.
	 */
	private static final String CREDENTIALS_JSON = "{\"AccessKeyId\":\"AKIA123456789012345\","
			+ "\"SecretAccessKey\":\"secret/1234567890123456789\",\"Token\":\"session-token\","
			+ "\"Expiration\":\"2099-01-01T00:00:00Z\",\"RoleArn\":\"arn:aws:iam::1:role/app\"}";

	@BeforeEach
	void prepareProvider() {
		env.clear();
		provider = new HostRoleCredentialsProvider() {
			@Override
			protected String getEnv(final String name) {
				return env.get(name);
			}
		};
		final var configuration = Mockito.mock(ConfigurationResource.class);
		Mockito.when(configuration.get(Mockito.anyString(), Mockito.anyString())).thenReturn(MOCK_URL);
		ReflectionTestUtils.setField(provider, "configuration", configuration);
		ReflectionTestUtils.setField(provider, "objectMapper", new ObjectMapperTrim());
	}

	@Test
	void getCredentialsContainerRelativeUri() {
		env.put("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/credentials/guid");
		httpServer.stubFor(
				get(urlEqualTo("/v2/credentials/guid")).willReturn(aResponse().withStatus(200).withBody(CREDENTIALS_JSON)));
		httpServer.start();

		final var credentials = provider.getCredentials();
		Assertions.assertEquals("AKIA123456789012345", credentials.accessKeyId());
		Assertions.assertEquals("secret/1234567890123456789", credentials.secretAccessKey());
		Assertions.assertEquals("session-token", credentials.token());
		Assertions.assertEquals(Instant.parse("2099-01-01T00:00:00Z"), credentials.expirationInstant());

		// Second call is served from the cache: the single stubbed hit is enough
		Assertions.assertSame(credentials, provider.getCredentials());
		httpServer.verify(1, getRequestedFor(urlEqualTo("/v2/credentials/guid")));
	}

	@Test
	void getCredentialsContainerFullUriWithToken() {
		env.put("AWS_CONTAINER_CREDENTIALS_FULL_URI", MOCK_URL + "/full-creds");
		env.put("AWS_CONTAINER_AUTHORIZATION_TOKEN", "Basic auth-token");
		httpServer.stubFor(get(urlEqualTo("/full-creds")).withHeader("Authorization", equalTo("Basic auth-token"))
				.willReturn(aResponse().withStatus(200).withBody(CREDENTIALS_JSON)));
		httpServer.start();

		Assertions.assertEquals("session-token", provider.getCredentials().token());
	}

	@Test
	void getCredentialsContainerTokenFile() throws IOException {
		final var tokenFile = Files.createTempFile("aws-auth", ".token");
		Files.writeString(tokenFile, "Bearer file-token\n");
		env.put("AWS_CONTAINER_CREDENTIALS_FULL_URI", MOCK_URL + "/full-creds");
		env.put("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", tokenFile.toString());
		httpServer.stubFor(get(urlEqualTo("/full-creds")).withHeader("Authorization", equalTo("Bearer file-token"))
				.willReturn(aResponse().withStatus(200).withBody(CREDENTIALS_JSON)));
		httpServer.start();

		Assertions.assertEquals("session-token", provider.getCredentials().token());
	}

	@Test
	void getCredentialsContainerTokenFileUnreadable() {
		// Unreadable token file: no Authorization header is sent, resolution proceeds
		env.put("AWS_CONTAINER_CREDENTIALS_FULL_URI", MOCK_URL + "/full-creds");
		env.put("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "/does/not/exist.token");
		httpServer.stubFor(get(urlEqualTo("/full-creds")).withHeader("Authorization", absent())
				.willReturn(aResponse().withStatus(200).withBody(CREDENTIALS_JSON)));
		httpServer.start();

		Assertions.assertEquals("session-token", provider.getCredentials().token());
	}

	@Test
	void getCredentialsImds() {
		httpServer.stubFor(put(urlEqualTo("/latest/api/token"))
				.withHeader("X-aws-ec2-metadata-token-ttl-seconds", equalTo("21600"))
				.willReturn(aResponse().withStatus(200).withBody("imds-token")));
		httpServer.stubFor(get(urlEqualTo("/latest/meta-data/iam/security-credentials/"))
				.withHeader("X-aws-ec2-metadata-token", equalTo("imds-token"))
				.willReturn(aResponse().withStatus(200).withBody("my-role\n")));
		httpServer.stubFor(get(urlEqualTo("/latest/meta-data/iam/security-credentials/my-role"))
				.withHeader("X-aws-ec2-metadata-token", equalTo("imds-token"))
				.willReturn(aResponse().withStatus(200).withBody(CREDENTIALS_JSON)));
		httpServer.start();

		final var credentials = provider.getCredentials();
		Assertions.assertEquals("AKIA123456789012345", credentials.accessKeyId());
		Assertions.assertEquals("session-token", credentials.token());
	}

	@Test
	void getCredentialsImdsNoRole() {
		// Token obtained, but no role listed → no credentials at all
		httpServer.stubFor(put(urlEqualTo("/latest/api/token"))
				.willReturn(aResponse().withStatus(200).withBody("imds-token")));
		httpServer.stubFor(get(urlEqualTo("/latest/meta-data/iam/security-credentials/"))
				.willReturn(aResponse().withStatus(200).withBody("")));
		httpServer.start();

		Assertions.assertThrows(IllegalStateException.class, provider::getCredentials);
	}

	@Test
	void getCredentialsNoSource() {
		// No container env, IMDS unreachable (404 on token)
		httpServer.stubFor(put(urlEqualTo("/latest/api/token")).willReturn(aResponse().withStatus(404)));
		httpServer.start();

		Assertions.assertThrows(IllegalStateException.class, provider::getCredentials);
	}

	@Test
	void getCredentialsUnparsablePayload() {
		env.put("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/credentials/guid");
		httpServer.stubFor(get(urlEqualTo("/v2/credentials/guid"))
				.willReturn(aResponse().withStatus(200).withBody("-not-json-")));
		// IMDS fallback also fails
		httpServer.stubFor(put(urlEqualTo("/latest/api/token")).willReturn(aResponse().withStatus(404)));
		httpServer.start();

		Assertions.assertThrows(IllegalStateException.class, provider::getCredentials);
	}

	@Test
	void getCredentialsExpiredRefreshes() {
		// Expired credentials in cache trigger a new resolution
		ReflectionTestUtils.setField(provider, "cached", new HostRoleCredentials("OLD", "OLD", "OLD",
				"2000-01-01T00:00:00Z"));
		env.put("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/credentials/guid");
		httpServer.stubFor(
				get(urlEqualTo("/v2/credentials/guid")).willReturn(aResponse().withStatus(200).withBody(CREDENTIALS_JSON)));
		httpServer.start();

		Assertions.assertEquals("session-token", provider.getCredentials().token());
	}

	@Test
	void expirationInstantEdgeCases() {
		// Absent or invalid expiration collapses to MIN → always considered expiring
		Assertions.assertEquals(Instant.MIN, new HostRoleCredentials("A", "S", "T", null).expirationInstant());
		Assertions.assertEquals(Instant.MIN, new HostRoleCredentials("A", "S", "T", "not-a-date").expirationInstant());
	}

	@Test
	void getEnvDefaultImplementation() {
		// The default implementation reads the real environment: PATH is always there
		Assertions.assertNotNull(new HostRoleCredentialsProvider().getEnv("PATH"));
	}
}
