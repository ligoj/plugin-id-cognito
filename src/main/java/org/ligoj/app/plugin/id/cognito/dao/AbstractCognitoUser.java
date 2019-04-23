/*
 * Licensed under MIT (https://github.com/ligoj/ligoj/blob/master/LICENSE)
 */
package org.ligoj.app.plugin.id.cognito.dao;

import java.util.Date;
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
public abstract class AbstractCognitoUser {

	/**
	 * User name: "976c1ce8-fb71-461a-8c06-e7e063cf8a1f"
	 */
	@JsonProperty("Username")
	private String username;

	@JsonProperty("Enabled")
	private boolean enabled;

	@JsonProperty("UserLastModifiedDate")
	private Date lastModifiedDate;

	/**
	 * Return the user attributes.
	 * 
	 * @return The user attributes.
	 */
	public abstract List<CognitoAttribute> getAttributes();
}
