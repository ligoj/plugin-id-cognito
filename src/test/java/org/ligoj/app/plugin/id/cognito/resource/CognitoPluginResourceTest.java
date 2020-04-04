/*
 * Licensed under MIT (https://github.com/ligoj/ligoj/blob/master/LICENSE)
 */
package org.ligoj.app.plugin.id.cognito.resource;

import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;

import javax.transaction.Transactional;

import org.apache.commons.io.IOUtils;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.ligoj.app.AbstractServerTest;
import org.ligoj.app.model.Node;
import org.ligoj.app.model.Parameter;
import org.ligoj.app.model.ParameterValue;
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

	@BeforeEach
	public void prepareData() throws IOException {
		persistEntities("csv", new Class[] { Node.class, Parameter.class, ParameterValue.class },
				StandardCharsets.UTF_8.name());
		// Invalidate cache
		cacheManager.getCache("container-scopes").clear();
		cacheManager.getCache("id-configuration").clear();
		cacheManager.getCache("curl-tokens").clear();
		cacheManager.getCache("node-parameters").clear();
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
		parameters.put(CognitoPluginResource.PARAMETER_SECRET_ACCESS_KEY, "abcdefghtiklmnopqrstuvwxyz");
		parameters.put(CognitoPluginResource.PARAMETER_POOL_ID, "eu-west-1_12345678");
		parameters.put(CognitoPluginResource.PARAMETER_REGION, "eu-west-1");
		Assertions.assertTrue(mockAws("cognito-describe-user-pool.json", "cognito-describe-user-pool.json")
				.checkStatus("service:id:cognito:test", parameters));
	}

	@Test
	public void checkStatusFailed() {
		final var parameters = new HashMap<String, String>();
		parameters.put(CognitoPluginResource.PARAMETER_ACCESS_KEY_ID, "12345678901234567890");
		parameters.put(CognitoPluginResource.PARAMETER_SECRET_ACCESS_KEY, "abcdefghtiklmnopqrstuvwxyz");
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

	@Test
	public void findAll() throws IOException {
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
		final var userOrg = users.getContent().get(0);
		Assertions.assertEquals("john", userOrg.getId());
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
		Assertions.assertEquals("jane", userOrg.getId());
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
		final var users = mockAws().getConfiguration("service:id:cognito:test").getUserRepository().findAllBy("name",
				"jane");
		final var userOrg = users.get(0);
		Assertions.assertEquals("jane", userOrg.getId());
		Assertions.assertEquals("00000000-0000-0000-0000-00000001", userOrg.getLocalId());
	}

	@Test
	public void findAllByNotFound() throws IOException {
		Assertions.assertEquals(0, mockAws().getConfiguration("service:id:cognito:test").getUserRepository()
				.findAllBy("mail", "any").size());
	}

	private CognitoPluginResource mockAws() throws IOException {
		return mockAws("cognito-describe-user-pool.json", "cognito-list-users.json", "cognito-admin-get-user.json",
				"cognito-admin-get-user.json");
	}

	private CognitoPluginResource mockAws(String... responseFiles) throws IOException {
		final var res = new ArrayList<>();
		for (var file : responseFiles) {
			res.add(IOUtils.toString(new ClassPathResource("mock-server/aws/" + file).getInputStream(), "UTF-8"));
		}
		return mockAws(HttpStatus.SC_OK, res.toArray(new String[0]));
	}

	private CognitoPluginResource mockAws(final int status, final String... responses) {
		configuration.put(CognitoPluginResource.CONF_HOST, MOCK_URL);
		final var resource = new CognitoPluginResource();
		applicationContext.getAutowireCapableBeanFactory().autowireBean(resource);
		resource.self = resource;
		for (var counter = 0; counter < responses.length; counter++) {
			httpServer.stubFor(post(urlEqualTo("/mock")).inScenario("Retry Scenario")
					.whenScenarioStateIs(counter == 0 ? "Started" : ("State" + counter))
					.willReturn(WireMock.aResponse().withStatus(status).withBody(responses[counter]))
					.willSetStateTo("State" + (counter + 1)));
		}

		// Coverage only
		resource.getKey();

		httpServer.start();
		return resource;
	}
}
