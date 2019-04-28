/*
 * Licensed under MIT (https://github.com/ligoj/ligoj/blob/master/LICENSE)
 */
package org.ligoj.app.plugin.id.resource;

import java.util.Optional;

import javax.cache.annotation.CacheResult;

import org.ligoj.app.iam.IamConfiguration;
import org.ligoj.app.iam.IamProvider;
import org.ligoj.app.plugin.id.cognito.resource.CognitoPluginResource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.security.core.Authentication;

/**
 * Cognito IAM provider.
 */
@Order(50)
public class CognitoIamProvider implements IamProvider {

	@Autowired
	protected CognitoPluginResource resource;

	private IamConfiguration iamConfiguration;

	@Autowired
	private CognitoIamProvider self;

	@Override
	public Authentication authenticate(final Authentication authentication) {
		// Primary authentication
		return resource.authenticate(authentication, "service:id:cognito:test", true);
	}

	@Override
	public IamConfiguration getConfiguration() {
		self.ensureCachedConfiguration();
		return Optional.ofNullable(iamConfiguration).orElseGet(this::refreshConfiguration);
	}

	@CacheResult(cacheName = "iam-cognito-configuration")
	public boolean ensureCachedConfiguration() {
		refreshConfiguration();
		return true;
	}

	private IamConfiguration refreshConfiguration() {
		this.iamConfiguration = resource.getConfiguration("service:id:cognito:test");
		return this.iamConfiguration;
	}

}
