/*
 * Licensed under MIT (https://github.com/ligoj/ligoj/blob/master/LICENSE)
 */
package org.ligoj.app.plugin.id.cognito.dao;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Getter;
import lombok.Setter;

/**
 * Cognito user attribute.
 */
@Getter
@Setter
public class CognitoAttribute {

	@JsonProperty("Name")
	private String name;

	@JsonProperty("Value")
	public String value;

}
