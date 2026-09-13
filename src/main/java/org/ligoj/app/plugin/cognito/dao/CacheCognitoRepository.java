/*
 * Licensed under MIT (https://github.com/ligoj/ligoj/blob/master/LICENSE)
 */
package org.ligoj.app.plugin.cognito.dao;

import java.util.Map;
import java.util.Optional;

import javax.cache.annotation.CacheResult;

import org.ligoj.app.iam.CompanyOrg;
import org.ligoj.app.iam.GroupOrg;
import org.ligoj.app.iam.ResourceOrg;
import org.ligoj.app.iam.UserOrg;
import org.ligoj.app.plugin.cognito.resource.IdCognitoCache;
import org.ligoj.app.plugin.id.dao.AbstractMemCacheRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

/**
 * In-memory Cognito data, refreshed from the user pool and pushed into the identity cache of plugin-id (companies,
 * users), like the LDAP plug-in does. The refresh is driven by the {@value IdCognitoCache#CACHE_DATA} cache entry.
 */
@Component
@Slf4j
public class CacheCognitoRepository extends AbstractMemCacheRepository {

	@Autowired
	protected CacheCognitoRepository self = this;

	@Override
	public Map<CacheDataType, Map<String, ? extends ResourceOrg>> getData() {
		self.ensureCachedData();
		return Optional.ofNullable(data).orElseGet(this::refreshData);
	}

	/**
	 * Ensure the fresh data is loaded, through the cache.
	 *
	 * @return <code>true</code>, required by JSR-107.
	 */
	@CacheResult(cacheName = IdCognitoCache.CACHE_DATA)
	public boolean ensureCachedData() {
		refreshData();
		return true;
	}

	@SuppressWarnings("unchecked")
	@Override
	protected synchronized Map<CacheDataType, Map<String, ? extends ResourceOrg>> refreshData() {
		final var now = System.currentTimeMillis();
		final var data = super.refreshData();
		cache.reset((Map<String, CompanyOrg>) data.get(CacheDataType.COMPANY),
				(Map<String, GroupOrg>) data.get(CacheDataType.GROUP),
				(Map<String, UserOrg>) data.get(CacheDataType.USER));
		log.info("Cognito identity cache refreshed in {}ms", System.currentTimeMillis() - now);
		return data;
	}
}
