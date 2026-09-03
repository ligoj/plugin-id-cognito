/*
 * Licensed under MIT (https://github.com/ligoj/ligoj/blob/master/LICENSE)
 */
package org.ligoj.app.plugin.cognito.auth;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.time.format.DateTimeParseException;

/**
 * Temporary AWS credentials as delivered by the host metadata endpoints — the EC2 instance profile (IMDSv2) and the
 * ECS/Fargate container credentials endpoint share this JSON shape.
 *
 * @param accessKeyId     The temporary access key.
 * @param secretAccessKey The temporary secret key.
 * @param token           The session token, to be signed as {@code x-amz-security-token}.
 * @param expiration      Expiry of these credentials (ISO-8601 string); refreshed ahead of it.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record HostRoleCredentials(@JsonProperty("AccessKeyId") String accessKeyId,
		@JsonProperty("SecretAccessKey") String secretAccessKey, @JsonProperty("Token") String token,
		@JsonProperty("Expiration") String expiration) {

	/**
	 * Parsed {@link #expiration()}, or {@link Instant#MIN} when absent/invalid so such credentials are always
	 * considered expiring and re-resolved.
	 *
	 * @return The expiration instant.
	 */
	public Instant expirationInstant() {
		try {
			return expiration == null ? Instant.MIN : Instant.parse(expiration);
		} catch (final DateTimeParseException dtpe) {
			return Instant.MIN;
		}
	}
}
