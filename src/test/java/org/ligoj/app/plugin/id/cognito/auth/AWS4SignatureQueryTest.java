/*
 * Licensed under MIT (https://github.com/ligoj/ligoj/blob/master/LICENSE)
 */
package org.ligoj.app.plugin.id.cognito.auth;

import java.util.Collections;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.ligoj.app.plugin.id.cognito.auth.AWS4SignatureQuery.AWS4SignatureQueryBuilder;

/**
 * Test class of {@link AWS4SignatureQuery}
 */
public class AWS4SignatureQueryTest {

	@Test
	public void builderNoHost() {
		Assertions.assertThrows(NullPointerException.class, () -> AWS4SignatureQuery.builder().build());
	}

	@Test
	public void builderNoPath() {
		Assertions.assertThrows(NullPointerException.class, () -> AWS4SignatureQuery.builder().host("myhost").build());
	}

	@Test
	public void builderNoService() {
		Assertions.assertThrows(NullPointerException.class, () -> AWS4SignatureQuery.builder().host("myhost").path("/").build());
	}

	@Test
	public void builderNoRegion() {
		Assertions.assertThrows(NullPointerException.class,
				() -> AWS4SignatureQuery.builder().host("myhost").path("/").service("ec2").build());
	}

	@Test
	public void builderNoAccessKey() {
		Assertions.assertThrows(NullPointerException.class,
				() -> AWS4SignatureQuery.builder().host("myhost").path("/").service("ec2").region("eu-west-1").build());
	}

	@Test
	public void builderNoSecretKey() {
		Assertions.assertThrows(NullPointerException.class, () -> AWS4SignatureQuery.builder().host("myhost").path("/").service("ec2")
				.region("eu-west-1").accessKey("--access-key--").build());
	}

	@Test
	public void builder() {
		var builder = AWS4SignatureQuery.builder();
		builder.toString();
		builder = builderCommon(builder);
		builder = builder.method("GET");
		builder.toString();
		Assertions.assertEquals("host", builder.service("s3").build().getHost());
	}

	@Test
	public void builderNullMethod() {
		final var builder = AWS4SignatureQuery.builder();
		builder.toString();
		Assertions.assertThrows(NullPointerException.class,()-> builderCommon(builder).method(null));
	}

	private AWS4SignatureQueryBuilder builderCommon(AWS4SignatureQueryBuilder builderParam) {
		var builder = builderParam;
		builder.toString();
		builder = builder.path("/");
		builder.toString();
		builder = builder.service("ec2");
		builder.toString();
		builder = builder.host("host");
		builder.toString();
		builder = builder.region("eu-west-1");
		builder.toString();
		builder = builder.accessKey("--access-key--");
		builder.toString();
		builder = builder.secretKey("--secret-key--");
		builder.toString();
		builder.build();
		builder = builder.body("-BODY-");
		builder.toString();
		builder = builder.headers(Collections.emptyMap());
		builder.toString();
		builder = builder.queryParameters(Collections.emptyMap());
		builder.toString();
		return builder;
	}
}
