/*
 * Licensed under MIT (https://github.com/ligoj/ligoj/blob/master/LICENSE)
 */
package org.ligoj.app.plugin.cognito.resource;

import java.util.Map;

import jakarta.transaction.Transactional;
import jakarta.transaction.Transactional.TxType;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

import org.apache.commons.lang3.StringUtils;
import org.ligoj.app.plugin.cognito.dao.UserCognitoRepository;
import org.ligoj.app.plugin.id.resource.AbstractPluginIdResource;
import org.ligoj.app.plugin.id.resource.IdentityResource;
import org.ligoj.bootstrap.core.SpringUtils;
import org.ligoj.bootstrap.core.validation.ValidationJsonException;
import org.ligoj.bootstrap.resource.system.configuration.ConfigurationResource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

/**
 * SQL resource.
 */
@Path(CognitoPluginResource.URL)
@Service
@Transactional
@Produces(MediaType.APPLICATION_JSON)
@Slf4j
public class CognitoPluginResource extends AbstractPluginIdResource<UserCognitoRepository> {

	/**
	 * Cognito API version.
	 */
	private static final String COGNITO_VERSION = "2016-04-18";

	/**
	 * Plug-in key.
	 */
	public static final String URL = IdentityResource.SERVICE_URL + "/cognito";

	/**
	 * Plug-in key.
	 */
	public static final String KEY = URL.replace('/', ':').substring(1);

	/**
	 * The default AWS Cognito URL pattern.
	 */
	private static final String URL_COGNITO = "https://cognito-idp.%s.amazonaws.com";

	/**
	 * Configuration key used for {@link #URL_COGNITO}
	 */
	public static final String CONF_HOST = KEY + ":url";

	/**
	 * Configuration key used for Cognito region.
	 */
	public static final String PARAMETER_REGION = KEY + ":region";

	/**
	 * Parameter used for AWS authentication
	 */
	public static final String PARAMETER_ACCESS_KEY_ID = KEY + ":access-key-id";

	/**
	 * Parameter used for AWS authentication
	 */
	public static final String PARAMETER_SECRET_ACCESS_KEY = KEY + ":secret-access-key";

	/**
	 * Cognito pool identifier.
	 */
	public static final String PARAMETER_POOL_ID = KEY + ":pool-id";

	/**
	 * Cognito's user attribute name to map as displayed user login.
	 */
	public static final String PARAMETER_ATTRIBUTE_ID = KEY + ":user-attribute-id";

	/**
	 * Default value of {@link #PARAMETER_ATTRIBUTE_ID}: the Cognito {@code sub}. In pre-authentication mode the
	 * login is the principal forwarded by the proxy (ALB header {@code X-Amzn-Oidc-Identity}), which is this
	 * {@code sub}, and {@link #accept(Authentication, String)} only takes such UUID principals. Keying the users by
	 * the same value lets the session decoration and the identity cache resolve the authenticated user.
	 */
	public static final String DEFAULT_ATTRIBUTE_ID = "sub";

	/**
	 * Cognito pool identifier.
	 */
	public static final String PARAMETER_LOGIN = KEY + ":pool-id";

	@Autowired
	@Getter
	protected CognitoPluginResource self;

	@Autowired
	protected ConfigurationResource configuration;

	@Override
	public boolean accept(final Authentication authentication, final String node) {
		return authentication.getName().matches("[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{8}");
	}

	@Override
	public String getVersion(final Map<String, String> parameters) {
		// Cognito version is fixed
		return COGNITO_VERSION;
	}

	@Override
	@Transactional(value = TxType.NOT_SUPPORTED)
	public String getKey() {
		return KEY;
	}

	@Override
	@Transactional(value = TxType.NOT_SUPPORTED)
	public String getLastVersion() {
		return COGNITO_VERSION;
	}

	@Override
	public boolean checkStatus(final String node, final Map<String, String> parameters) {
		return ((UserCognitoRepository) self.getConfiguration(node).getUserRepository()).refreshPoolName() != null;
	}

	/**
	 * Build a user Cognito repository from the given node.
	 *
	 * @param node The node to request.
	 * @return The {@link UserCognitoRepository} instance. Cache is not involved.
	 */
	@Override
	protected UserCognitoRepository getUserRepository(final String node) {
		log.info("Build Cognito template for node {}", node);

		// A new repository instance
		return getUserRepository(pvResource.getNodeParameters(node));
	}

	/**
	 * Build a user Cognito repository from the given node.
	 *
	 * @param parameters The node parameters to request.
	 * @return The {@link UserCognitoRepository} instance. Cache is not involved.
	 */
	private UserCognitoRepository getUserRepository(final Map<String, String> parameters) {
		// The mandatory parameters: a tool node, or an incomplete instance, must not break the sessions with an NPE
		for (final var mandatory : new String[]{PARAMETER_REGION, PARAMETER_POOL_ID}) {
			if (StringUtils.isBlank(parameters.get(mandatory))) {
				log.error("Cognito node parameter '{}' is not defined: the node designated by 'feature:iam:node:primary'"
						+ " must be a configured instance node, not the tool node", mandatory);
				throw new ValidationJsonException(mandatory, "NotBlank");
			}
		}

		// A new repository instance
		final var repository = new UserCognitoRepository();
		final var region = parameters.get(PARAMETER_REGION);
		repository.setRegion(region);
		repository.setAccessKey(parameters.get(PARAMETER_ACCESS_KEY_ID));
		repository.setSecretKey(parameters.get(PARAMETER_SECRET_ACCESS_KEY));
		repository.setPoolId(parameters.get(PARAMETER_POOL_ID));
		repository.setAttributeId(StringUtils.defaultIfBlank(parameters.get(PARAMETER_ATTRIBUTE_ID), DEFAULT_ATTRIBUTE_ID));
		repository.setUrl(configuration.get(CONF_HOST, URL_COGNITO).replace("%s", region));

		// Complete the bean
		SpringUtils.getApplicationContext().getAutowireCapableBeanFactory().autowireBean(repository);
		repository.refreshPoolName();
		return repository;
	}

}
