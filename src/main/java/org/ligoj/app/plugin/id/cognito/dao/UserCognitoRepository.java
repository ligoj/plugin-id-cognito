/*
 * Licensed under MIT (https://github.com/ligoj/ligoj/blob/master/LICENSE)
 */
package org.ligoj.app.plugin.id.cognito.dao;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;
import org.ligoj.app.iam.CompanyOrg;
import org.ligoj.app.iam.GroupOrg;
import org.ligoj.app.iam.ICompanyRepository;
import org.ligoj.app.iam.IGroupRepository;
import org.ligoj.app.iam.IUserRepository;
import org.ligoj.app.iam.UserOrg;
import org.ligoj.app.iam.empty.EmptyCompanyRepository;
import org.ligoj.app.iam.empty.EmptyGroupRepository;
import org.ligoj.app.plugin.id.cognito.auth.AWS4SignatureQuery;
import org.ligoj.app.plugin.id.cognito.auth.AWS4SignatureQuery.AWS4SignatureQueryBuilder;
import org.ligoj.app.plugin.id.cognito.auth.AWS4SignerCognitoForAuthorizationHeader;
import org.ligoj.app.plugin.id.model.LoginComparator;
import org.ligoj.bootstrap.core.curl.CurlProcessor;
import org.ligoj.bootstrap.core.curl.CurlRequest;
import org.ligoj.bootstrap.core.json.ObjectMapperTrim;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;

import jodd.bean.BeanUtil;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

/**
 * User Cognito repository
 */
@Slf4j
public class UserCognitoRepository implements IUserRepository {

	/**
	 * Default {@link IGroupRepository}.
	 */
	private static final IGroupRepository GROUP_REPOSITORY = new EmptyGroupRepository();

	/**
	 * Default {@link ICompanyRepository}.
	 */
	private static final ICompanyRepository COMPANY_REPOSITORY = new EmptyCompanyRepository();

	/**
	 * User comparator for ordering
	 */
	public static final Comparator<UserOrg> DEFAULT_COMPARATOR = new LoginComparator();

	private static final Map<String, BiFunction<UserOrg, String, Boolean>> SEARCH_MAPPER = new HashMap<>();
	static {
		SEARCH_MAPPER.put("mails", (u, v) -> u.getMails().contains(v));
		SEARCH_MAPPER.put("mail", SEARCH_MAPPER.get("mails"));
	}

	private BeanUtil beanutils = BeanUtil.declaredSilent;

	/**
	 * Base DN for internal people. Should be a subset of people, so including {@link #peopleBaseDn}
	 */
	@Getter
	private String peopleInternalBaseDn = "ou=internal,ou=people";

	/**
	 * AWS region.
	 */
	@Setter
	private String region;

	/**
	 * AWS service host.
	 */
	@Setter
	private String url;

	/**
	 * AWS access key.
	 */
	@Setter
	private String secretKey;

	/**
	 * AWS secret key.
	 */
	@Setter
	private String accessKey;

	/**
	 * Cognito Pool id.
	 */
	@Setter
	private String poolId;

	private String poolName;

	@Autowired
	private AWS4SignerCognitoForAuthorizationHeader signer = new AWS4SignerCognitoForAuthorizationHeader();

	@Autowired
	private ObjectMapperTrim objectMapper;

	@Override
	public UserOrg create(final UserOrg user) {
		// Not yet implemented
		return null;
	}

	@Override
	public UserOrg findByIdNoCache(final String localId) {
		return newRequest("AdminGetUser", "{\"Username\": \"" + localId + "\", \"UserPoolId\": \"" + poolId + "\"}",
				CognitoUser.class, this::toUser);
	}

	/**
	 * Create Curl request for AWS service. Initialize default values for awsAccessKey, awsSecretKey and regionName and
	 * compute signature.
	 *
	 * @param action The Cognito's action.
	 * @param body   The Cognito's request.
	 * @param clazz  The target object class.
	 * @param mapper The function mapping to the target object.
	 * @param <T>    Response type built from the JSON and to converter with the mapper.
	 * @param <U>    Return type.
	 * @return The object mapped from the HTTP response.
	 */
	public <T, U> U newRequest(final String action, final String body, final Class<T> clazz,
			final Function<T, U> mapper) {
		final var request = newRequest(action, body);
		try (var curl = new CurlProcessor()) {
			if (curl.process(request)) {
				return mapper.apply(objectMapper.readValue(request.getResponse(), clazz));
			}
		} catch (final IOException e) {
			log.info("Unable to parse Cognito response {}", request.getResponse(), e);
		}
		return null;
	}

	/**
	 * Create Curl request for AWS service. Initialize default values for awsAccessKey, awsSecretKey and regionName and
	 * compute signature.
	 *
	 * @param action The Cognito's action.
	 * @param body   The Cognito's request.
	 * @return The initialized request.
	 */
	public CurlRequest newRequest(final String action, final String body) {
		final AWS4SignatureQueryBuilder builder = AWS4SignatureQuery.builder().service("cognito-idp")
				.body("&Version=2016-04-18");
		final var headers = new HashMap<String, String>();
		headers.put("x-amz-target", "AWSCognitoIdentityProviderService." + action);
		headers.put("Content-Type", "application/x-amz-json-1.1");
		final AWS4SignatureQuery query = builder.accessKey(accessKey).secretKey(secretKey).region(region).path("/")
				.headers(headers).body(body).host(URI.create(url).getHost()).build();
		final var authorization = signer.computeSignature(query);
		final var request = new CurlRequest(query.getMethod(), url, query.getBody());
		request.getHeaders().putAll(query.getHeaders());
		request.getHeaders().put("Authorization", authorization);
		request.setSaveResponse(true);
		return request;
	}

	@Override
	public List<UserOrg> findAllBy(final String attribute, final String value) {
		// Not yet implemented
		return findAll().values().stream()
				.filter(u -> Optional.ofNullable(SEARCH_MAPPER.get(attribute)).map(f -> f.apply(u, value)).orElseGet(
						() -> value.equalsIgnoreCase(String.valueOf((Object) beanutils.getProperty(u, attribute)))))
				.collect(Collectors.toList());
	}

	@Override
	public Map<String, UserOrg> findAll() {
		// Not yet implemented
		return findAllNoCache(null);
	}

	@Override
	public Map<String, UserOrg> findAllNoCache(final Map<String, GroupOrg> groups) {
		// Not yet implemented
		return ObjectUtils.defaultIfNull(
				newRequest("ListUsers", "{\"Limit\": 60,\"UserPoolId\": \"" + poolId + "\"}", CognitoListUsers.class,
						l -> l.getUsers().stream().map(this::toUser)
								.collect(Collectors.toMap(UserOrg::getId, Function.identity()))),
				Collections.emptyMap());
	}

	@Override
	public String toDn(UserOrg newUser) {
		return "uid=" + newUser.getLocalId() + ",ou=" + poolName;
	}

	/**
	 * Build a {@link UserOrg} object. The key attributes are:
	 * <ul>
	 * <li>id : corresponds to the desired user name as displayed to user. It may be changed if this user is taken by
	 * another user from another IAM provider.</li>
	 * <li>localId : corresponds to the Cognito user identifier, a 128bit String, unique in the Cognito Pool.</li>
	 * <li>company : corresponds to the Cognito pool name, not its identifier.</li>
	 * </ul>
	 * 
	 * @see <a href="https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html">User
	 *      pool attributes</a>
	 * @param entity The Cognito result.
	 * @return The corresponding {@link UserOrg} object.
	 */
	private UserOrg toUser(final AbstractCognitoUser entity) {
		final var attr = entity.getAttributes().stream()
				.collect(Collectors.toMap(CognitoAttribute::getName, CognitoAttribute::getValue));
		final var user = new UserOrg();
		user.setDn(buildDn(entity.getUsername(), "pool=" + poolId));
		user.setFirstName(attr.getOrDefault("given_name", attr.getOrDefault("name", attr.get("nickname"))));
		user.setLastName(attr.get("family_name"));
		user.setLocalId(entity.getUsername());
		user.setId(attr.getOrDefault("nickname", attr.get("email")));
		user.setCompany(poolName);
		user.setSecured("true".equals(attr.get("email_verified")));
		user.setLocked(entity.isEnabled() ? null : entity.getLastModifiedDate());
		user.setMails(Arrays.asList(attr.get("email")));
		return user;
	}

	/**
	 * Return DN from entry.
	 *
	 * @param login     The user login to create.
	 * @param companyDn The target company DN.
	 * @return DN from entry.
	 */
	private String buildDn(final String login, final String companyDn) {
		return "uid=" + login + "," + companyDn;
	}

	@Override
	public Page<UserOrg> findAll(final Collection<GroupOrg> requiredGroups, final Set<String> companies,
			final String criteria, final Pageable pageable) {
		// Not yet implemented
		return new PageImpl<>(new ArrayList<>(findAll().values()));
	}

	@Override
	public void updateMembership(final Collection<String> groups, final UserOrg user) {
		// Not yet implemented
	}

	@Override
	public void updateUser(final UserOrg user) {
		// Not yet implemented
	}

	@Override
	public void delete(final UserOrg user) {
		// Not yet implemented
	}

	@Override
	public void lock(final String principal, final UserOrg user) {
		// Not yet implemented
	}

	@Override
	public void isolate(final String principal, final UserOrg user) {
		// Not yet implemented
	}

	@Override
	public void restore(final UserOrg user) {
		// Not yet implemented
	}

	@Override
	public void move(final UserOrg user, final CompanyOrg company) {
		// Not yet implemented
	}

	@Override
	public void unlock(final UserOrg user) {
		// Not yet implemented
	}

	@Override
	public boolean authenticate(final String name, final String password) {
		// "name" corresponds to the Cognito's "Username" property
		return StringUtils.isNoneBlank(name) && StringUtils.isNoneBlank(password) && findByIdNoCache(name) != null;
	}

	@Override
	public String getToken(final String login) {
		return login;
	}

	@Override
	public void setPassword(final UserOrg user, final String password) {
		// Not yet implemented
	}

	@Override
	public void setPassword(final UserOrg user, final String password, final String newPassword) {
		// Not yet implemented
	}

	@Override
	public IGroupRepository getGroupRepository() {
		// Not yet implemented
		return GROUP_REPOSITORY;
	}

	@Override
	public ICompanyRepository getCompanyRepository() {
		// Not yet implemented
		return COMPANY_REPOSITORY;
	}

	/**
	 * Refresh and return the Cognito pool name from its identifier.
	 * 
	 * @return The pool name.
	 */
	public String refreshPoolName() {
		poolName = newRequest("DescribeUserPool", "{\"UserPoolId\": \"" + poolId + "\"}", CognitoUserPool.class,
				u -> u.getUserpool().getName());
		return poolName;
	}
}
