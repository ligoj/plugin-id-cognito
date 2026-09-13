/*
 * Licensed under MIT (https://github.com/ligoj/ligoj/blob/master/LICENSE)
 */
package org.ligoj.app.plugin.cognito.resource;

import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import jakarta.transaction.Transactional;

import org.apache.commons.io.IOUtils;
import org.apache.hc.core5.http.HttpStatus;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.ligoj.app.AbstractServerTest;
import org.ligoj.app.model.Node;
import org.ligoj.app.model.Parameter;
import org.ligoj.app.model.ParameterValue;
import org.ligoj.app.plugin.cognito.resource.CognitoPluginResource;
import org.ligoj.bootstrap.core.validation.ValidationJsonException;
import org.ligoj.bootstrap.resource.system.configuration.ConfigurationResource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.test.annotation.Rollback;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.stubbing.Scenario;
import org.ligoj.app.iam.dao.CacheCompanyRepository;
import org.ligoj.app.iam.dao.CacheUserRepository;
import org.springframework.data.domain.PageRequest;

/**
 * Test class of {@link CognitoPluginResource}
 */
@ExtendWith(SpringExtension.class)
@ContextConfiguration(locations = "classpath:/META-INF/spring/application-context-test.xml")
@Rollback
@Transactional
public class CognitoPluginResourceTest extends AbstractServerTest {

	private static final String MOCK_URL = "http://localhost:" + MOCK_PORT + "/mock";

	@Autowired
	private CognitoPluginResource resource;

	@Autowired
	private ConfigurationResource configuration;

	@Autowired
	private CacheUserRepository cacheUserRepository;

	@Autowired
	private CacheCompanyRepository cacheCompanyRepository;

	@BeforeEach
	public void prepareData() throws IOException {
		persistEntities("csv", new Class[]{Node.class, Parameter.class, ParameterValue.class},
				StandardCharsets.UTF_8);
		// Invalidate cache
		cacheManager.getCache("container-scopes").clear();
		cacheManager.getCache("id-configuration").clear();
		cacheManager.getCache("curl-tokens").clear();
		cacheManager.getCache("node-parameters").clear();
		cacheManager.getCache("iam-cognito-configuration").clear();
		cacheManager.getCache("id-cognito-data").clear();
	}

	@Test
	public void getVersion() {
		final var version = resource.getVersion(null);
		Assertions.assertEquals("2016-04-18", version);
	}

	@Test
	public void getLastVersion() {
		final var lastVersion = resource.getLastVersion();
		Assertions.assertEquals("2016-04-18", lastVersion);
	}

	@Test
	public void checkStatus() throws IOException {
		final var parameters = new HashMap<String, String>();
		parameters.put(CognitoPluginResource.PARAMETER_ACCESS_KEY_ID, "12345678901234567890");
		parameters.put(CognitoPluginResource.PARAMETER_SECRET_ACCESS_KEY, "secret_secret_secret");
		parameters.put(CognitoPluginResource.PARAMETER_POOL_ID, "eu-west-1_12345678");
		parameters.put(CognitoPluginResource.PARAMETER_REGION, "eu-west-1");
		Assertions.assertTrue(mockAws("cognito-describe-user-pool.json", "cognito-describe-user-pool.json")
				.checkStatus("service:id:cognito:test", parameters));
	}

	/**
	 * A node without the mandatory parameters (the tool node itself, or an incomplete instance) is refused with a
	 * validation error naming the parameter, instead of a NullPointerException breaking every session.
	 */
	@Test
	public void getConfigurationMissingRegion() {
		em.createQuery("DELETE FROM ParameterValue WHERE parameter.id = :id")
				.setParameter("id", CognitoPluginResource.PARAMETER_REGION).executeUpdate();
		em.flush();
		final var resource = mockAws(400, "");
		final var error = Assertions.assertThrows(ValidationJsonException.class,
				() -> resource.getConfiguration("service:id:cognito:test"));
		Assertions.assertTrue(error.getErrors().containsKey(CognitoPluginResource.PARAMETER_REGION), error.getErrors().toString());
	}

	@Test
	public void getConfigurationMissingPoolId() {
		em.createQuery("DELETE FROM ParameterValue WHERE parameter.id = :id")
				.setParameter("id", CognitoPluginResource.PARAMETER_POOL_ID).executeUpdate();
		em.flush();
		final var resource = mockAws(400, "");
		final var error = Assertions.assertThrows(ValidationJsonException.class,
				() -> resource.getConfiguration("service:id:cognito:test"));
		Assertions.assertTrue(error.getErrors().containsKey(CognitoPluginResource.PARAMETER_POOL_ID), error.getErrors().toString());
	}

	@Test
	public void checkStatusFailed() {
		final var parameters = new HashMap<String, String>();
		parameters.put(CognitoPluginResource.PARAMETER_ACCESS_KEY_ID, "12345678901234567890");
		parameters.put(CognitoPluginResource.PARAMETER_SECRET_ACCESS_KEY, "secret_secret_secret");
		parameters.put(CognitoPluginResource.PARAMETER_POOL_ID, "eu-west-1_12345678");
		parameters.put(CognitoPluginResource.PARAMETER_REGION, "eu-west-1");
		Assertions.assertFalse(mockAws(400, "").checkStatus("service:id:cognito:test", parameters));
	}

	@Test
	public void acceptNotMatch() {
		Assertions.assertFalse(resource.accept(new UsernamePasswordAuthenticationToken("some", ""), null));
	}

	@Test
	public void accept() {
		Assertions.assertTrue(
				resource.accept(new UsernamePasswordAuthenticationToken("00000000-0000-0000-0000-00000000", ""), null));
	}

	@Test
	public void authenticate() throws IOException {
		final var authentication = new UsernamePasswordAuthenticationToken("00000000-0000-0000-0000-00000000", "-");
		Assertions.assertSame(authentication, mockAws("cognito-describe-user-pool.json", "cognito-admin-get-user.json")
				.authenticate(authentication, "service:id:cognito:test", true));
	}

	@Test
	public void authenticateInvalidPayload() {
		final Authentication authentication = new UsernamePasswordAuthenticationToken(
				"00000000-0000-0000-0000-00000000", "-");
		Assertions.assertThrows(BadCredentialsException.class,
				() -> mockAws("cognito-invalid.json").authenticate(authentication, "service:id:cognito:test", true));
	}

	@Test
	public void authenticateNoName() {
		final var authentication = new UsernamePasswordAuthenticationToken(null, "-");
		Assertions.assertThrows(BadCredentialsException.class,
				() -> mockAws("cognito-describe-user-pool.json", "cognito-admin-get-user.json")
						.authenticate(authentication, "service:id:cognito:test", true));
	}

	@Test
	public void authenticateNoCred() {
		final var authentication = new UsernamePasswordAuthenticationToken("00000000-0000-0000-0000-00000000", " ");
		Assertions.assertThrows(BadCredentialsException.class,
				() -> mockAws("cognito-describe-user-pool.json", "cognito-admin-get-user.json")
						.authenticate(authentication, "service:id:cognito:test", true));
	}

	@Test
	public void authenticateFail() {
		final var authentication = new UsernamePasswordAuthenticationToken("any", "any");
		Assertions.assertThrows(BadCredentialsException.class, () -> {
			mockAws(400, "").authenticate(authentication, "service:id:cognito:test", true);
		});
	}

	/**
	 * Without {@code service:id:cognito:user-attribute-id}, the identifier is the Cognito {@code sub}: the principal
	 * forwarded by the pre-authentication header (ALB {@code X-Amzn-Oidc-Identity}), the only one {@code accept()}
	 * takes.
	 */
	@Test
	public void findAllDefaultIdSub() throws IOException {
		final var users = mockAws().getConfiguration("service:id:cognito:test").getUserRepository().findAll();
		final var userOrg = users.get("00000000-0000-0000-0000-00000000");
		Assertions.assertEquals("00000000-0000-0000-0000-00000000", userOrg.getId());
		Assertions.assertEquals("00000000-0000-0000-0000-00000000", userOrg.getLocalId());
		Assertions.assertEquals("john", userOrg.getFirstName());
		Assertions.assertEquals("john.doe@sample.com", userOrg.getMails().get(0));
		Assertions.assertNull(users.get("john"));
	}

	/**
	 * Every Cognito attribute is exposed as a custom attribute, so that {@code service:id:user-display} can name one
	 * of them ({@code preferred_username}, {@code nickname}, {@code custom:*}, ...); the UI falls back to the login
	 * when the attribute is missing for a user.
	 */
	@Test
	public void findAllCustomAttributes() throws IOException {
		final var users = mockAws().getConfiguration("service:id:cognito:test").getUserRepository().findAll();
		final var john = users.get("00000000-0000-0000-0000-00000000");
		Assertions.assertEquals("johnny", john.getCustomAttributes().get("preferred_username"));
		Assertions.assertEquals("john", john.getCustomAttributes().get("nickname"));
		Assertions.assertEquals("00000000-0000-0000-0000-00000000", john.getCustomAttributes().get("sub"));
		final var jane = users.get("00000000-0000-0000-0000-00000001");
		Assertions.assertFalse(jane.getCustomAttributes().containsKey("preferred_username"));
		Assertions.assertEquals("jane", jane.getCustomAttributes().get("nickname"));
	}

	@Test
	public void findAllIdNickname() throws IOException {
		final var value = new ParameterValue();
		value.setData("nickname");
		value.setParameter(em.find(Parameter.class, "service:id:cognito:user-attribute-id"));
		value.setNode(em.find(Node.class, "service:id:cognito:test"));
		em.persist(value);

		final var users = mockAws().getConfiguration("service:id:cognito:test").getUserRepository().findAll();
		final var userOrg = users.get("john");
		Assertions.assertEquals("john", userOrg.getId());
		Assertions.assertEquals("00000000-0000-0000-0000-00000000", userOrg.getLocalId());
		Assertions.assertEquals("john", userOrg.getFirstName());
		Assertions.assertEquals("john.doe@sample.com", userOrg.getMails().get(0));
	}

	@Test
	public void findAllIdEmail() throws IOException {
		final var value = new ParameterValue();
		value.setData("email");
		value.setParameter(em.find(Parameter.class, "service:id:cognito:user-attribute-id"));
		value.setNode(em.find(Node.class, "service:id:cognito:test"));
		em.persist(value);

		final var users = mockAws().getConfiguration("service:id:cognito:test").getUserRepository().findAll();
		final var userOrg = users.get("john.doe@sample.com");
		Assertions.assertEquals("john.doe@sample.com", userOrg.getId());
		Assertions.assertEquals("00000000-0000-0000-0000-00000000", userOrg.getLocalId());
		Assertions.assertEquals("john", userOrg.getFirstName());
		Assertions.assertEquals("john.doe@sample.com", userOrg.getMails().get(0));
	}

	@Test
	public void findAllSearch() throws IOException {
		final var users = mockAws().getConfiguration("service:id:cognito:test").getUserRepository().findAll(null, null,
				null, null);
		Assertions.assertEquals(2, users.getContent().size());
		final var userOrg = users.getContent().stream()
				.filter(u -> "00000000-0000-0000-0000-00000000".equals(u.getLocalId())).findFirst().orElseThrow();
		Assertions.assertEquals("00000000-0000-0000-0000-00000000", userOrg.getId());
		Assertions.assertEquals("00000000-0000-0000-0000-00000000", userOrg.getLocalId());
		Assertions.assertEquals("john", userOrg.getFirstName());
		Assertions.assertEquals("john.doe@sample.com", userOrg.getMails().get(0));
		Assertions.assertNull(userOrg.getLocked());
	}

	@Test
	public void toDn() throws IOException {
		final var repository = mockAws("cognito-describe-user-pool.json", "cognito-admin-get-user.json")
				.getConfiguration("service:id:cognito:test").getUserRepository();
		final var user = repository.findByIdNoCache("00000000-0000-0000-0000-00000000");
		final String dn = repository.toDn(user);
		Assertions.assertEquals("uid=00000000-0000-0000-0000-00000000,ou=kloudy", dn);
	}

	@Test
	public void coverageOnly() throws IOException {
		final var repository = mockAws("cognito-describe-user-pool.json", "cognito-admin-get-user.json")
				.getConfiguration("service:id:cognito:test").getUserRepository();
		repository.create(null);
		repository.updateMembership(null, null);
		repository.delete(null);
		repository.updateUser(null);
		repository.lock(null, null);
		repository.isolate(null, null);
		repository.restore(null);
		repository.move(null, null);
		repository.unlock(null);
		Assertions.assertEquals("any", repository.getToken("any"));
		repository.setPassword(null, null);
		repository.setPassword(null, null, null);
		repository.getPeopleInternalBaseDn();
		Assertions.assertNotNull(repository.getCompanyRepository());
		Assertions.assertNotNull(repository.getGroupRepository());
	}

	@Test
	public void findAllByMail() throws IOException {
		final var users = mockAws().getConfiguration("service:id:cognito:test").getUserRepository().findAllBy("mail",
				"jane.doe@sample.com");
		final var userOrg = users.get(0);
		Assertions.assertEquals("00000000-0000-0000-0000-00000001", userOrg.getId());
		Assertions.assertEquals("00000000-0000-0000-0000-00000001", userOrg.getLocalId());
		Assertions.assertNotNull(userOrg.getLocked());
	}

	@Test
	public void findAllByUnknownProperty() throws IOException {
		final var users = mockAws().getConfiguration("service:id:cognito:test").getUserRepository().findAllBy("foo",
				"bar");
		Assertions.assertEquals(0, users.size());
	}

	@Test
	public void findAllBy() throws IOException {
		final var users = mockAws().getConfiguration("service:id:cognito:test").getUserRepository()
				.findAllBy("firstName", "jane");
		final var userOrg = users.get(0);
		Assertions.assertEquals("00000000-0000-0000-0000-00000001", userOrg.getId());
		Assertions.assertEquals("00000000-0000-0000-0000-00000001", userOrg.getLocalId());
	}

	@Test
	public void findAllByNotFound() throws IOException {
		Assertions.assertEquals(0, mockAws().getConfiguration("service:id:cognito:test").getUserRepository()
				.findAllBy("mail", "any").size());
	}

	/**
	 * The company check of {@link org.ligoj.app.iam.IUserRepository#findByIdExpected(String, String)} (used by the
	 * session decoration) passes: the Cognito user belongs to the pool company, known by the company repository.
	 */
	@Test
	public void findByIdExpectedPrincipal() throws IOException {
		final var repository = mockAws().getConfiguration("service:id:cognito:test").getUserRepository();
		final var user = repository.findByIdExpected("someone-else", "00000000-0000-0000-0000-00000000");
		Assertions.assertEquals("kloudy", user.getCompany());
		Assertions.assertEquals("john.doe@sample.com", user.getMails().getFirst());
		Assertions.assertNotNull(user.getGroups());
		Assertions.assertTrue(user.getGroups().isEmpty());
	}

	/**
	 * The company repository exposes the user pool as the single company.
	 */
	@Test
	public void companyRepository() throws IOException {
		final var companies = mockAws().getConfiguration("service:id:cognito:test").getUserRepository()
				.getCompanyRepository();
		final var pool = companies.findAll().get("kloudy");
		Assertions.assertNotNull(pool);
		Assertions.assertEquals("kloudy", pool.getName());
		Assertions.assertEquals("pool=eu-west-1_12345678", pool.getDn());
		Assertions.assertSame(pool, companies.findById("anyone", "kloudy"));
		Assertions.assertEquals("company", companies.getTypeName());
		Assertions.assertEquals(1, companies.findAll(null, "KLO", PageRequest.of(0, 10), null).getTotalElements());
		Assertions.assertEquals(0, companies.findAll(null, "other", PageRequest.of(0, 10), null).getTotalElements());
	}

	/**
	 * Listing the users feeds the identity cache of plugin-id (companies and users), used by the delegation
	 * queries and the system users page.
	 */
	@Test
	public void findAllFeedsCache() throws IOException {
		final var repository = mockAws().getConfiguration("service:id:cognito:test").getUserRepository();
		final var users = repository.findAll();
		Assertions.assertEquals(2, users.size());
		// Served from the cache: same data until the cache is invalidated
		Assertions.assertSame(users, repository.findAll());

		final var cacheUser = cacheUserRepository.findById("00000000-0000-0000-0000-00000000").orElseThrow();
		Assertions.assertEquals("john.doe@sample.com", cacheUser.getMails());
		Assertions.assertEquals("john", cacheUser.getFirstName());
		Assertions.assertEquals("kloudy", cacheUser.getCompany().getId());
		Assertions.assertEquals("pool=eu-west-1_12345678", cacheCompanyRepository.findById("kloudy").orElseThrow().getDescription());
	}

	/**
	 * ListUsers answers at most 60 users per call: the pages are followed through the pagination token.
	 */
	@Test
	public void findAllNoCachePaginated() throws IOException {
		final var repository = mockAws("cognito-describe-user-pool.json", "cognito-list-users-page1.json",
				"cognito-list-users-page2.json").getConfiguration("service:id:cognito:test").getUserRepository();
		final var users = repository.findAllNoCache(null);
		Assertions.assertEquals(2, users.size());
		Assertions.assertTrue(users.containsKey("00000000-0000-0000-0000-00000000"));
		Assertions.assertTrue(users.containsKey("00000000-0000-0000-0000-00000001"));
		// The second call carried the token of the first page
		httpServer.verify(1, postRequestedFor(urlEqualTo("/mock")).withRequestBody(containing("\"PaginationToken\": \"next-page\"")));
	}

	/**
	 * Cognito action answered by each mock file.
	 */
	private static final Map<String, String> ACTIONS = Map.of("cognito-describe-user-pool.json", "DescribeUserPool",
			"cognito-list-users.json", "ListUsers", "cognito-list-users-page1.json", "ListUsers",
			"cognito-list-users-page2.json", "ListUsers", "cognito-admin-get-user.json", "AdminGetUser",
			"cognito-invalid.json", "AdminGetUser");

	private CognitoPluginResource mockAws() throws IOException {
		return mockAws("cognito-describe-user-pool.json", "cognito-list-users.json", "cognito-admin-get-user.json");
	}

	/**
	 * Mock the Cognito endpoint with the given response files. Each file answers its own action (see
	 * {@link #ACTIONS}); several files of the same action are served in order, the last one being repeated.
	 */
	private CognitoPluginResource mockAws(final String... responseFiles) throws IOException {
		final var byAction = new LinkedHashMap<String, List<String>>();
		for (final var file : responseFiles) {
			byAction.computeIfAbsent(ACTIONS.get(file), _ -> new ArrayList<>()).add(
					IOUtils.toString(new ClassPathResource("mock-server/aws/" + file).getInputStream(), StandardCharsets.UTF_8));
		}
		final var resource = newResource();
		byAction.forEach((action, responses) -> {
			for (var counter = 0; counter < responses.size(); counter++) {
				final var last = counter == responses.size() - 1;
				httpServer.stubFor(post(urlEqualTo("/mock"))
						.withHeader("x-amz-target", equalTo("AWSCognitoIdentityProviderService." + action))
						.inScenario(action).whenScenarioStateIs(counter == 0 ? Scenario.STARTED : "State" + counter)
						.willReturn(WireMock.aResponse().withStatus(HttpStatus.SC_OK).withBody(responses.get(counter)))
						.willSetStateTo(last ? (counter == 0 ? Scenario.STARTED : "State" + counter) : "State" + (counter + 1)));
			}
		});
		return resource;
	}

	/**
	 * Mock the Cognito endpoint answering the given status and body to every action.
	 */
	private CognitoPluginResource mockAws(final int status, final String body) {
		final var resource = newResource();
		httpServer.stubFor(post(urlEqualTo("/mock")).willReturn(WireMock.aResponse().withStatus(status).withBody(body)));
		return resource;
	}

	private CognitoPluginResource newResource() {
		configuration.put(CognitoPluginResource.CONF_HOST, MOCK_URL);
		final var resource = new CognitoPluginResource();
		applicationContext.getAutowireCapableBeanFactory().autowireBean(resource);
		resource.self = resource;

		// Coverage only
		Assertions.assertEquals("service:id:cognito", resource.getKey());
		httpServer.start();
		return resource;
	}
}
