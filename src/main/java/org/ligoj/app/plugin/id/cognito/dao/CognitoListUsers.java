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
 * Cognito user pool.
 * @see <a href="https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListUsers.html">ListUsers</a>
 */
@Getter
@Setter
@JsonIgnoreProperties(ignoreUnknown = true)
public class CognitoListUsers {

	@JsonProperty("Users")
	private List<CognitoUserFromList> users = new ArrayList<>();
}
