/*
 * Licensed under MIT (https://github.com/ligoj/ligoj/blob/master/LICENSE)
 */
package org.ligoj.app.plugin.cognito.dao;

import java.util.Comparator;
import java.util.Map;
import java.util.Set;

import org.apache.commons.lang3.StringUtils;
import org.ligoj.app.iam.CompanyOrg;
import org.ligoj.app.iam.ICompanyRepository;
import org.ligoj.app.plugin.id.dao.AbstractMemCacheRepository.CacheDataType;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

/**
 * Company repository of a Cognito user pool: the pool itself is the single, read-only company of every user, so
 * the delegation checks of plugin-id (user lookup, visible companies) resolve. Served from the shared cache.
 */
public class CompanyCognitoRepository implements ICompanyRepository {

	private final UserCognitoRepository users;

	/**
	 * @param users The user repository owning the pool identifier and name.
	 */
	CompanyCognitoRepository(final UserCognitoRepository users) {
		this.users = users;
	}

	@Override
	@SuppressWarnings("unchecked")
	public Map<String, CompanyOrg> findAll() {
		return (Map<String, CompanyOrg>) users.getCacheRepository().getData().get(CacheDataType.COMPANY);
	}

	@Override
	public Map<String, CompanyOrg> findAllNoCache() {
		final var pool = users.newPoolCompany();
		return Map.of(pool.getId(), pool);
	}

	@Override
	public Page<CompanyOrg> findAll(final Set<CompanyOrg> companies, final String criteria, final Pageable pageable,
			final Map<String, Comparator<CompanyOrg>> customComparators) {
		final var matching = findAll().values().stream()
				.filter(c -> StringUtils.isBlank(criteria) || StringUtils.containsIgnoreCase(c.getName(), criteria))
				.toList();
		return new PageImpl<>(matching, pageable, matching.size());
	}

	@Override
	public CompanyOrg create(final String dn, final String name) {
		// Read-only: the pool is the only company
		return new CompanyOrg(dn, name);
	}

	@Override
	public void delete(final CompanyOrg container) {
		// Read-only: the pool is the only company
	}

	@Override
	public String getTypeName() {
		return "company";
	}
}
