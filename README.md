## :link: Ligoj Identity AWS Cognito plugin [![Maven Central](https://maven-badges.herokuapp.com/maven-central/org.ligoj.plugin/plugin-id-cognito/badge.svg)](https://maven-badges.herokuapp.com/maven-central/org.ligoj.plugin/plugin-id-cognito) [![Download](https://api.bintray.com/packages/ligoj/maven-repo/plugin-id-cognito/images/download.svg) ](https://bintray.com/ligoj/maven-repo/plugin-id-cognito/_latestVersion)

[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=org.ligoj.plugin%3Aplugin-id-cognito&metric=coverage)](https://sonarcloud.io/dashboard?id=org.ligoj.plugin%3Aplugin-id-cognito)
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?metric=alert_status&project=org.ligoj.plugin:plugin-id-cognito)](https://sonarcloud.io/dashboard/index/org.ligoj.plugin:plugin-id-cognito)
[![License](http://img.shields.io/:license-mit-blue.svg)](http://fabdouglas.mit-license.org/)

[Ligoj](https://github.com/ligoj/ligoj) AWS Cognito identity plugin, and extending [Identity plugin](https://github.com/ligoj/plugin-id)

Requires [IAM Node plugin](https://github.com/ligoj/plugin-iam-node) to select this node as reference for authentication.

The node designated by `feature:iam:node:primary` must be a configured **instance** node (for example
`service:id:cognito:saas`, created from the node administration page with the region and the user pool id), not the
`service:id:cognito` tool node: without the region and the pool id, the node is refused with a validation error
naming the missing parameter, and the sessions carry no user details.

Required IAM Policy looks like [this](src/main/resources/META-INF/resources/webjars/service/id/cognito/aws-policy.json)


## User identifier and displayed name

The Ligoj login of a Cognito user is the value of the `service:id:cognito:user-attribute-id` attribute, `sub` by
default. In pre-authentication mode (ALB / Cognito, `security.pre-auth-principal=X-Amzn-Oidc-Identity`), the
principal forwarded to Ligoj is this `sub`: with the default, the session details, the identity cache and the system
users page (`/#/system/user`) all resolve the authenticated user. Set the parameter to `email` or `nickname` only when
the forwarded principal is that attribute. Refresh the identity cache (or restart the API) after changing it.

The user pool is exposed as the single company of every user (DN `pool=<pool id>`, named after the pool), and the
pool content (users, company) is pushed into the identity cache of plugin-id, like the LDAP plug-in does: the
Identity pages list the Cognito users and the pool, the system users page (`/#/system/user`) shows names and mails,
and the session of an authenticated user carries its details. The pool is read with `ListUsers`, following the
pagination tokens. This data is kept in the `id-cognito-data` cache (one day): after a change in the pool,
invalidate it from the cache administration page, or with `ligoj cache invalidate`, or restart the API.

Every Cognito attribute (`sub`, `email`, `preferred_username`, `nickname`, `custom:*`, ...) is exposed as a custom
attribute of the user. To display something else than the login in the top-right button, set the global
configuration `service:id:user-display` (see [plugin-id](https://github.com/ligoj/plugin-id)):

| Value                | Displayed                                                             |
|----------------------|-----------------------------------------------------------------------|
| `mail`               | The Cognito `email` (`mail-short` drops the domain part)              |
| `preferred_username` | The Cognito `preferred_username`, the login when the user has none    |
| `${firstName} ${lastName}` | Expression over the attributes, the login when one is missing   |

## Authentication to AWS

The node parameters `service:id:cognito:access-key-id` and `service:id:cognito:secret-access-key` are optional.
When either is empty, the plugin uses the **host-provided role** instead — no AWS SDK involved:

1. ECS/Fargate task role, through the container credentials endpoint
   (`AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` or `AWS_CONTAINER_CREDENTIALS_FULL_URI`, with optional
   `AWS_CONTAINER_AUTHORIZATION_TOKEN[_FILE]`);
2. EC2 instance profile, through IMDSv2 (token handshake).

Temporary credentials are cached and refreshed 5 minutes before their expiration, and the session token is
signed within each request (`x-amz-security-token`). The metadata endpoints are configurable for tests or
non-standard environments: `service:id:cognito:ecs-credentials-url` (default `http://169.254.170.2`) and
`service:id:cognito:imds-url` (default `http://169.254.169.254`).
