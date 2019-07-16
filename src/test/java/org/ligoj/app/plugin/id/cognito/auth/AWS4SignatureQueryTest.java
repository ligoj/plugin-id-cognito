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
	void builder() {
		AWS4SignatureQueryBuilder builder = AWS4SignatureQuery.builder();
		builder.toString();
		builder = builderCommon(builder);
		builder = builder.method("GET");
		builder.toString();
		Assertions.assertEquals("host", builder.service("s3").build().getHost());
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
