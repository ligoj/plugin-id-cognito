/*
 * Licensed under MIT (https://github.com/ligoj/ligoj/blob/master/LICENSE)
 */
package org.ligoj.app.plugin.id.cognito.resource;

import java.util.Map;

import javax.transaction.Transactional;
import javax.transaction.Transactional.TxType;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import org.ligoj.app.plugin.id.cognito.dao.UserCognitoRepository;
import org.ligoj.app.plugin.id.resource.AbstractPluginIdResource;
import org.ligoj.app.plugin.id.resource.IdentityResource;
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
	 * Cognito user attribute name to map as displayed user login.
	 */
	public static final String PARAMETER_ATTRIBUTE_ID = KEY + ":user-attribute-id";

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
		// A new repository instance
		final UserCognitoRepository repository = new UserCognitoRepository();
		final String region = parameters.get(PARAMETER_REGION);
		repository.setRegion(region);
		repository.setAccessKey(parameters.get(PARAMETER_ACCESS_KEY_ID));
		repository.setSecretKey(parameters.get(PARAMETER_SECRET_ACCESS_KEY));
		repository.setPoolId(parameters.get(PARAMETER_POOL_ID));
		repository.setAttributeId(parameters.getOrDefault(PARAMETER_ATTRIBUTE_ID, "nickname"));
		repository.setUrl(configuration.get(CONF_HOST, URL_COGNITO).replace("%s", region));

		// Complete the bean
		context.getAutowireCapableBeanFactory().autowireBean(repository);
		repository.refreshPoolName();
		return repository;
	}

}
