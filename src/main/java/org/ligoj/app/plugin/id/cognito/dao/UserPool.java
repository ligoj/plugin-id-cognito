/*
 * Licensed under MIT (https://github.com/ligoj/ligoj/blob/master/LICENSE)
 */
package org.ligoj.app.plugin.id.cognito.dao;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Getter;
import lombok.Setter;

/**
 * Cognito user pool attribute.
 * 
 * @see <a href=
 *      "https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DescribeUserPool.html">DescribeUserPool</a>
 */
@Getter
@Setter
@JsonIgnoreProperties(ignoreUnknown = true)
public class UserPool {
	@JsonProperty("Name")
	private String name;
}
