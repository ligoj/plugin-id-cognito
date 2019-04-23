/*
 * Licensed under MIT (https://github.com/ligoj/ligoj/blob/master/LICENSE)
 */
/**
 * 
 */
package org.ligoj.app.plugin.id.cognito.auth;

import java.time.Clock;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * Test class of {@link AWS4SignerCognitoForAuthorizationHeader}
 */
public class AWS4SignerCognitoForAuthorizationHeaderTest {

	/**
	 * signer
	 */
	final private AWS4SignerCognitoForAuthorizationHeader signer = new AWS4SignerCognitoForAuthorizationHeader();

	@Test
	public void testComputeSignature() {
		ReflectionTestUtils.setField(signer, "clock", Clock
				.fixed(LocalDateTime.of(2017, 5, 29, 22, 15).toInstant(ZoneOffset.UTC), ZoneOffset.UTC.normalized()));
		final AWS4SignatureQuery signatureQuery = AWS4SignatureQuery.builder().accessKey("awsAccessKey")
				.secretKey("awsSecretKey").region("eu-west-1").method("GET").host("my_host").service("s3").path("path").build();
		Assertions.assertEquals(
				"AWS4-HMAC-SHA256 Credential=awsAccessKey/20170529/eu-west-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=e9dd5966c2675df7cf581ecfe8264920ccb508b23b8690ae806bb5799c4116ee",
				signer.computeSignature(signatureQuery));
	}

	@Test
	public void testComputeSignatureWithBody() {
		ReflectionTestUtils.setField(signer, "clock", Clock
				.fixed(LocalDateTime.of(2017, 5, 29, 22, 15).toInstant(ZoneOffset.UTC), ZoneOffset.UTC.normalized()));
		final AWS4SignatureQuery signatureQuery = AWS4SignatureQuery.builder().accessKey("awsAccessKey")
				.secretKey("awsSecretKey").region("eu-west-1").method("GET").host("my_host").service("s3").path("path").body("body")
				.build();
		Assertions.assertEquals(
				"AWS4-HMAC-SHA256 Credential=awsAccessKey/20170529/eu-west-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=1e61b82dde37acf8dd16d5d6ffaed689c8315045169aeec0e72f1003a6c0102e",
				signer.computeSignature(signatureQuery));
	}

}
