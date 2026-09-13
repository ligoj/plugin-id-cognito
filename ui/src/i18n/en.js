// Flat-key EN messages: Cognito parameter labels (from the legacy
// `nls/messages.js`) and the wizard group label.
export default {
  'service:id:cognito:access-key-id': 'Access Key Id',
  'service:id:cognito:secret-access-key': 'Secret Access Key',
  'service:id:cognito:region': 'Cognito region',
  'service:id:cognito:pool-id': 'Cognito Pool Id',
  'service:id:cognito:user-attribute-id': 'User attribute for id',
  'service:id:cognito:user-attribute-id-description': "Cognito attribute used as the Ligoj login. Default: sub, the principal forwarded in pre-authentication mode (ALB X-Amzn-Oidc-Identity). Every Cognito attribute is also exposed as a custom attribute, so service:id:user-display may name one of them (mail, preferred_username, nickname, custom:…), with the login as fallback.",
  'service:id:cognito:access-key-id-description': "Leave empty (with the secret key) to use the host-provided role: ECS/Fargate task role or EC2 instance profile",
  'service:id:cognito:secret-access-key-description': "Leave empty (with the access key) to use the host-provided role: ECS/Fargate task role or EC2 instance profile",
  'id.cognito.wizard.connection': 'AWS connection',
}
