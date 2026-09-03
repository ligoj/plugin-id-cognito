/*
 * Licensed under MIT (https://github.com/ligoj/ligoj/blob/master/LICENSE)
 */
package org.ligoj.app.plugin.cognito.auth;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.ligoj.bootstrap.core.curl.CurlProcessor;
import org.ligoj.bootstrap.core.json.ObjectMapperTrim;
import org.ligoj.bootstrap.core.curl.CurlRequest;
import org.ligoj.bootstrap.resource.system.configuration.ConfigurationResource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.Instant;

/**
 * Host-provided AWS role credentials, used when the node has no static access/secret key: the ECS/Fargate task role
 * (container credentials endpoint) is tried first, then the EC2 instance profile (IMDSv2). No AWS SDK involved — both
 * endpoints are plain HTTP + JSON, fetched with the stack's own {@link CurlProcessor}.
 *
 * Credentials are cached and refreshed ahead of their expiration. Endpoints are configurable (tests, exotic
 * environments) through {@link ConfigurationResource}:
 * <ul>
 * <li>{@code service:id:cognito:ecs-credentials-url} — container credentials base, default
 * {@code http://169.254.170.2}</li>
 * <li>{@code service:id:cognito:imds-url} — instance metadata service base, default
 * {@code http://169.254.169.254}</li>
 * </ul>
 */
@Slf4j
@Component
public class HostRoleCredentialsProvider {

	/**
	 * Configuration key of the ECS/Fargate container credentials endpoint base URL.
	 */
	public static final String CONF_ECS_URL = "service:id:cognito:ecs-credentials-url";

	/**
	 * Configuration key of the EC2 instance metadata service base URL.
	 */
	public static final String CONF_IMDS_URL = "service:id:cognito:imds-url";

	private static final String DEFAULT_ECS_URL = "http://169.254.170.2";
	private static final String DEFAULT_IMDS_URL = "http://169.254.169.254";

	/**
	 * Refresh margin before the actual expiration.
	 */
	private static final Duration REFRESH_MARGIN = Duration.ofMinutes(5);

	@Autowired
	protected ConfigurationResource configuration;

	@Autowired
	protected ObjectMapperTrim objectMapper;

	private volatile HostRoleCredentials cached;

	/**
	 * Return the host-provided role credentials, from cache when still valid.
	 *
	 * @return The valid credentials.
	 * @throws IllegalStateException When no host credentials source is available.
	 */
	public HostRoleCredentials getCredentials() {
		var credentials = cached;
		if (isExpiring(credentials)) {
			synchronized (this) {
				credentials = cached;
				if (isExpiring(credentials)) {
					credentials = resolve();
					cached = credentials;
				}
			}
		}
		return credentials;
	}

	private boolean isExpiring(final HostRoleCredentials credentials) {
		return credentials == null || Instant.now().isAfter(credentials.expirationInstant().minus(REFRESH_MARGIN));
	}

	/**
	 * Resolve fresh credentials: ECS/Fargate container endpoint first, then EC2 IMDSv2.
	 */
	private HostRoleCredentials resolve() {
		var credentials = resolveContainer();
		if (credentials == null) {
			credentials = resolveImds();
		}
		if (credentials == null) {
			throw new IllegalStateException("No AWS credentials: node parameters are empty and no host-provided role"
					+ " is reachable (neither ECS/Fargate container endpoint nor EC2 instance metadata)");
		}
		log.info("Host-provided AWS role credentials resolved, expiring at {}", credentials.expiration());
		return credentials;
	}

	/**
	 * ECS/Fargate task role: {@code AWS_CONTAINER_CREDENTIALS_RELATIVE_URI} (against the link-local base) or
	 * {@code AWS_CONTAINER_CREDENTIALS_FULL_URI}, optionally authorized by
	 * {@code AWS_CONTAINER_AUTHORIZATION_TOKEN[_FILE]}.
	 */
	private HostRoleCredentials resolveContainer() {
		final var relativeUri = getEnv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI");
		final var fullUri = getEnv("AWS_CONTAINER_CREDENTIALS_FULL_URI");
		if (StringUtils.isAllBlank(relativeUri, fullUri)) {
			return null;
		}
		final var url = StringUtils.isNotBlank(relativeUri)
				? configuration.get(CONF_ECS_URL, DEFAULT_ECS_URL) + relativeUri
				: fullUri;
		final var request = new CurlRequest("GET", url, null);
		final var token = getContainerAuthorization();
		if (token != null) {
			request.getHeaders().put("Authorization", token);
		}
		return parse(execute(request));
	}

	/**
	 * Return the container endpoint authorization, plain value or file-provided (Fargate), null when unset.
	 */
	private String getContainerAuthorization() {
		final var token = getEnv("AWS_CONTAINER_AUTHORIZATION_TOKEN");
		if (StringUtils.isNotBlank(token)) {
			return token;
		}
		final var tokenFile = getEnv("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE");
		if (StringUtils.isNotBlank(tokenFile)) {
			try {
				return Files.readString(Paths.get(tokenFile)).trim();
			} catch (final IOException ioe) {
				log.warn("Unreadable AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE {}", tokenFile, ioe);
			}
		}
		return null;
	}

	/**
	 * EC2 instance profile through IMDSv2: session token, then role name, then its credentials.
	 */
	private HostRoleCredentials resolveImds() {
		final var base = configuration.get(CONF_IMDS_URL, DEFAULT_IMDS_URL);
		final var tokenRequest = new CurlRequest("PUT", base + "/latest/api/token", null);
		tokenRequest.getHeaders().put("X-aws-ec2-metadata-token-ttl-seconds", "21600");
		final var token = execute(tokenRequest);
		if (token == null) {
			return null;
		}
		final var roleBase = base + "/latest/meta-data/iam/security-credentials/";
		final var role = execute(imdsGet(roleBase, token));
		if (StringUtils.isBlank(role)) {
			return null;
		}
		return parse(execute(imdsGet(roleBase + role.lines().findFirst().orElse("").trim(), token)));
	}

	private CurlRequest imdsGet(final String url, final String token) {
		final var request = new CurlRequest("GET", url, null);
		request.getHeaders().put("X-aws-ec2-metadata-token", token);
		return request;
	}

	/**
	 * Execute the request and return the raw response, null on any failure.
	 */
	private String execute(final CurlRequest request) {
		request.setSaveResponse(true);
		try (var curl = new CurlProcessor()) {
			if (curl.process(request)) {
				return request.getResponse();
			}
		}
		return null;
	}

	/**
	 * Parse the metadata JSON payload, null when absent or invalid.
	 */
	private HostRoleCredentials parse(final String json) {
		if (json == null) {
			return null;
		}
		try {
			final var credentials = objectMapper.readValue(json, HostRoleCredentials.class);
			return credentials.accessKeyId() == null ? null : credentials;
		} catch (final tools.jackson.core.JacksonException je) {
			log.warn("Unparsable host credentials payload", je);
			return null;
		}
	}

	/**
	 * Environment access, overridable for tests.
	 *
	 * @param name The environment variable name.
	 * @return The value or null.
	 */
	protected String getEnv(final String name) {
		return System.getenv(name);
	}
}
