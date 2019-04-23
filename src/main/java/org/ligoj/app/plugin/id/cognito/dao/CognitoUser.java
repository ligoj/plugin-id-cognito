/*
 * Licensed under MIT (https://github.com/ligoj/ligoj/blob/master/LICENSE)
 */
package org.ligoj.app.plugin.id.cognito.dao;

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Getter;
import lombok.Setter;

/**
 * Cognito user data.
 */
@Getter
@Setter
@JsonIgnoreProperties(ignoreUnknown = true)
public class CognitoUser extends AbstractCognitoUser {

	@JsonProperty("UserAttributes")
	private List<CognitoAttribute> attributes = new ArrayList<>();
}
