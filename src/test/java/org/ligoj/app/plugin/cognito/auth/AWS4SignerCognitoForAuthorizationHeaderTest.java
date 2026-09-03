/*
 * Licensed under MIT (https://github.com/ligoj/ligoj/blob/master/LICENSE)
 */
package org.ligoj.app.plugin.cognito.auth;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.ligoj.app.plugin.cognito.auth.AWS4SignatureQuery;
import org.ligoj.app.plugin.cognito.auth.AWS4SignerCognitoForAuthorizationHeader;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Clock;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

/**
 * Test class of {@link AWS4SignerCognitoForAuthorizationHeader}
 */
public class AWS4SignerCognitoForAuthorizationHeaderTest {

	/**
	 * signer
	 */
	final private AWS4SignerCognitoForAuthorizationHeader signer = new AWS4SignerCognitoForAuthorizationHeader();

	/**
	 * Test method for
	 * {@link AWS4SignerCognitoForAuthorizationHeader#computeSignature(AWS4SignatureQuery)}.
	 */
	@Test
	void testComputeSignature() {
		ReflectionTestUtils.setField(signer, "clock", Clock
				.fixed(LocalDateTime.of(2017, 5, 29, 22, 15).toInstant(ZoneOffset.UTC), ZoneOffset.UTC.normalized()));
		final var signatureQuery = AWS4SignatureQuery.builder().accessKey("awsAccessKey").secretKey("awsSecretKey")
				.region("eu-west-1").method("GET").service("s3").path("path").build();
		Assertions.assertEquals(
				"AWS4-HMAC-SHA256 Credential=awsAccessKey/20170529/eu-west-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=6a48aa41b25ea6d1b0e636c78ea971de060256ea2a2b2e6b103d6fbf14c7d21a",
				signer.computeSignature(signatureQuery));
	}

	/**
	 * Temporary credentials (host-provided role): the security token is added to the signed headers.
	 */
	@Test
	void testComputeSignatureWithSessionToken() {
		ReflectionTestUtils.setField(signer, "clock", Clock
				.fixed(LocalDateTime.of(2017, 5, 29, 22, 15).toInstant(ZoneOffset.UTC), ZoneOffset.UTC.normalized()));
		final var signatureQuery = AWS4SignatureQuery.builder().accessKey("awsAccessKey").secretKey("awsSecretKey")
				.sessionToken("session-token").region("eu-west-1").method("GET").service("s3").path("path").build();
		final var authorization = signer.computeSignature(signatureQuery);
		Assertions.assertEquals("session-token", signatureQuery.getHeaders().get("x-amz-security-token"));
		Assertions.assertTrue(authorization.contains("x-amz-security-token"),
				"The security token must be part of the signed headers: " + authorization);
	}

	/**
	 * Test method for
	 * {@link AWS4SignerCognitoForAuthorizationHeader#computeSignature(AWS4SignatureQuery)}.
	 */
	@Test
	void testComputeSignatureWithBody() {
		ReflectionTestUtils.setField(signer, "clock", Clock
				.fixed(LocalDateTime.of(2017, 5, 29, 22, 15).toInstant(ZoneOffset.UTC), ZoneOffset.UTC.normalized()));
		final var signatureQuery = AWS4SignatureQuery.builder().accessKey("awsAccessKey").secretKey("awsSecretKey")
				.region("eu-west-1").method("GET").service("s3").path("path").body("body").build();
		Assertions.assertEquals(
				"AWS4-HMAC-SHA256 Credential=awsAccessKey/20170529/eu-west-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=704a07b30cf11a27123ea3b430680a37ffe311a858496440ab519d0cc5adaa8f",
				signer.computeSignature(signatureQuery));
	}

}
