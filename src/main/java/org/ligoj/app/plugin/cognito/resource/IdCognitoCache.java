/*
 * Licensed under MIT (https://github.com/ligoj/ligoj/blob/master/LICENSE)
 */
package org.ligoj.app.plugin.cognito.resource;

import javax.cache.expiry.Duration;

import org.ligoj.bootstrap.resource.system.cache.CacheManagerAware;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Role;
import org.springframework.stereotype.Component;

import com.hazelcast.cache.HazelcastCacheManager;
import org.ligoj.bootstrap.resource.system.cache.CacheConfigurer;

/**
 * Cache configuration of the Cognito identity data: the user pool content (users, the pool company) fed into the
 * identity cache of plugin-id. Invalidate {@code id-cognito-data} after a change in the pool.
 */
@Component
@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
public class IdCognitoCache implements CacheManagerAware {

	/**
	 * Cache name of the Cognito identity data.
	 */
	public static final String CACHE_DATA = "id-cognito-data";

	@Override
	public void onCreate(final HazelcastCacheManager cacheManager, final CacheConfigurer configurer) {
		cacheManager.createCache(CACHE_DATA, configurer.newCacheConfig(CACHE_DATA, Duration.ONE_DAY));
	}
}
