/*
 * Licensed under MIT (https://github.com/ligoj/ligoj/blob/master/LICENSE)
 */
package org.ligoj.app.plugin.cognito.dao;

import jodd.bean.BeanUtil;
import tools.jackson.core.JacksonException;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.ligoj.app.iam.*;
import org.ligoj.app.iam.empty.EmptyGroupRepository;
import org.ligoj.app.plugin.cognito.auth.AWS4SignatureQuery;
import org.ligoj.app.plugin.cognito.auth.HostRoleCredentialsProvider;
import org.ligoj.app.plugin.cognito.auth.AWS4SignerCognitoForAuthorizationHeader;
import org.ligoj.app.plugin.id.dao.AbstractMemCacheRepository.CacheDataType;
import org.ligoj.app.plugin.id.dao.UserCriteria;
import org.ligoj.app.plugin.id.model.LoginComparator;
import org.ligoj.bootstrap.core.curl.CurlProcessor;
import org.ligoj.bootstrap.core.curl.CurlRequest;
import org.ligoj.bootstrap.core.json.ObjectMapperTrim;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;

import java.net.URI;
import java.util.*;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.stream.Collectors;

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
	 * Maximum users returned by one ListUsers call (Cognito limit).
	 */
	private static final int LIST_USERS_LIMIT = 60;

	/**
	 * Default {@link ICompanyRepository}.
	 */
	/**
	 * The pool as the single company, built once the pool name is known.
	 */
	private ICompanyRepository companyRepository;

	/**
	 * Shared identity cache, fed from the pool.
	 */
	@Getter
	@Setter
	@Autowired
	private CacheCognitoRepository cacheRepository;

	/**
	 * User comparator for ordering
	 */
	public static final Comparator<UserOrg> DEFAULT_COMPARATOR = new LoginComparator();

	private static final Map<String, BiFunction<UserOrg, String, Boolean>> SEARCH_MAPPER = new HashMap<>();

	static {
		SEARCH_MAPPER.put("mails", (u, v) -> u.getMails().contains(v));
		SEARCH_MAPPER.put("mail", SEARCH_MAPPER.get("mails"));
	}

	private final BeanUtil beanutils = BeanUtil.declaredSilent;

	/**
	 * Base DN for internal people. Should be a subset of people, so including {@link #getPeopleInternalBaseDn()}
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

	/**
	 * Cognito user attribute to use as identifier.
	 */
	@Setter
	private String attributeId;

	@Autowired
	private final AWS4SignerCognitoForAuthorizationHeader signer = new AWS4SignerCognitoForAuthorizationHeader();

	@Autowired
	private ObjectMapperTrim objectMapper;

	/**
	 * Host-provided role credentials, used when the node carries no static access/secret key.
	 */
	@Setter
	@Autowired
	private HostRoleCredentialsProvider hostRoleCredentialsProvider;

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
		} catch (final JacksonException je) {
			// Not a JSON payload of the expected shape: same as a failed request
			log.warn("Unexpected Cognito response for action {}: {}", action, je.getMessage());
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
		final var builder = AWS4SignatureQuery.builder().service("cognito-idp").body("&Version=2016-04-18");
		final var headers = new HashMap<String, String>();
		headers.put("x-amz-target", "AWSCognitoIdentityProviderService." + action);
		headers.put("Content-Type", "application/x-amz-json-1.1");
		// Static node credentials, or the host-provided role (EC2 instance profile / ECS-Fargate task role)
		var queryAccessKey = accessKey;
		var querySecretKey = secretKey;
		String querySessionToken = null;
		if (StringUtils.isAnyBlank(accessKey, secretKey)) {
			final var credentials = hostRoleCredentialsProvider.getCredentials();
			queryAccessKey = credentials.accessKeyId();
			querySecretKey = credentials.secretAccessKey();
			querySessionToken = credentials.token();
		}
		final var query = builder.accessKey(queryAccessKey).secretKey(querySecretKey)
				.sessionToken(querySessionToken).region(region).path("/").headers(headers)
				.body(body).host(URI.create(url).getHost()).build();
		final var authorization = signer.computeSignature(query);
		final var request = new CurlRequest(query.getMethod(), url, query.getBody());
		request.getHeaders().putAll(query.getHeaders());
		request.getHeaders().put("Authorization", authorization);
		request.setSaveResponse(true);
		return request;
	}

	@SuppressWarnings("cast")
	@Override
	public List<UserOrg> findAllBy(final String attribute, final String value) {
		// Not yet implemented
		return findAll().values().stream()
				.filter(u -> Optional.ofNullable(SEARCH_MAPPER.get(attribute)).map(f -> f.apply(u, value)).orElseGet(
						() -> value.equalsIgnoreCase(String.valueOf((Object) beanutils.getProperty(u, attribute)))))
				.toList();
	}

	@Override
	@SuppressWarnings("unchecked")
	public Map<String, UserOrg> findAll() {
		return (Map<String, UserOrg>) cacheRepository.getData().get(CacheDataType.USER);
	}

	/**
	 * List every user of the pool, following the pagination tokens: ListUsers answers at most
	 * {@value #LIST_USERS_LIMIT} users per call.
	 */
	@Override
	public Map<String, UserOrg> findAllNoCache(final Map<String, GroupOrg> groups) {
		final var result = new HashMap<String, UserOrg>();
		String token = null;
		do {
			final var body = "{\"Limit\": " + LIST_USERS_LIMIT + ",\"UserPoolId\": \"" + poolId + "\""
					+ (token == null ? "" : ", \"PaginationToken\": \"" + token + "\"") + "}";
			final var page = newRequest("ListUsers", body, CognitoListUsers.class, Function.identity());
			if (page == null) {
				break;
			}
			page.getUsers().stream().map(this::toUser).forEach(u -> result.put(u.getId(), u));
			token = StringUtils.trimToNull(page.getPaginationToken());
		} while (token != null);
		return result;
	}

	/**
	 * The user pool as a company: DN {@code pool=<poolId>}, named after the pool.
	 *
	 * @return A new company instance of the pool.
	 */
	CompanyOrg newPoolCompany() {
		return new CompanyOrg("pool=" + poolId, poolName);
	}

	@Override
	public String toDn(UserOrg newUser) {
		return "uid=" + newUser.getLocalId() + ",ou=" + poolName;
	}

	/**
	 * Build a {@link UserOrg} object. The key attributes are:
	 * <ul>
	 * <li>id : corresponds to the desired username as displayed to user. It may be changed if this user is taken by
	 * another user from another IAM provider.</li>
	 * <li>localId : corresponds to the Cognito user identifier, a 128bit String, unique in the Cognito Pool.</li>
	 * <li>company : corresponds to the Cognito pool name, not its identifier.</li>
	 * </ul>
	 *
	 * @param entity The Cognito result.
	 * @return The corresponding {@link UserOrg} object.
	 * @see <a href="https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html">User
	 * pool attributes</a>
	 */
	private UserOrg toUser(final AbstractCognitoUser entity) {
		final var attr = entity.getAttributes().stream()
				.collect(Collectors.toMap(CognitoAttribute::getName, CognitoAttribute::getValue));
		final var user = new UserOrg();
		user.setDn(buildDn(entity.getUsername(), "pool=" + poolId));
		user.setFirstName(attr.getOrDefault("given_name", attr.getOrDefault("name", attr.get("nickname"))));
		user.setLastName(attr.get("family_name"));
		user.setLocalId(entity.getUsername());
		user.setId(StringUtils.lowerCase(
				Objects.toString(attr.getOrDefault(attributeId, attr.get("email")), entity.getUsername())));
		user.setCompany(newPoolCompany().getId());
		user.setGroups(new ArrayList<>());
		user.setSecured("true".equals(attr.get("email_verified")));
		user.setLocked(entity.isEnabled() && entity.getLastModifiedDate() != null ? null : entity.getLastModifiedDate().toInstant());
		user.setMails(Collections.singletonList(attr.get("email")));
		// Every Cognito attribute ("sub", "preferred_username", "nickname", "custom:*", ...) is exposed as a custom
		// attribute: "service:id:user-display" (or "service:id:visual-id-name") may name one of them, and the UI
		// falls back to the login when a user has no such attribute.
		user.setCustomAttributes(new HashMap<>(attr));
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
		// No group in a pool: only the free-text criterion applies (login, names, mail, custom attributes such as
		// "preferred_username"), then the requested page, sorted by login
		final var matching = findAll().values().stream().filter(u -> UserCriteria.matches(u, criteria))
				.sorted(DEFAULT_COMPARATOR).toList();
		if (pageable == null || pageable.isUnpaged()) {
			return new PageImpl<>(matching);
		}
		final var from = (int) Math.min(pageable.getOffset(), matching.size());
		final var to = Math.min(from + pageable.getPageSize(), matching.size());
		return new PageImpl<>(matching.subList(from, to), pageable, matching.size());
	}

	@Override
	public UserUpdateResult updateMembership(final Collection<String> groups, final UserOrg user) {
		// Not yet implemented
		return null;
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
	public UserOrg authenticate(final String name, final String password) {
		// "name" corresponds to the Cognito's "Username" property
		if (StringUtils.isNotBlank(name) && StringUtils.isNotBlank(password)) {
			return findByIdNoCache(name);
		}
		return null;
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
		if (companyRepository == null) {
			companyRepository = new CompanyCognitoRepository(this);
		}
		return companyRepository;
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
