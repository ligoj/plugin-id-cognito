// Flat-key FR messages (legacy `nls/fr/messages.js`, completed).
export default {
  'service:id:cognito:access-key-id': 'Access Key Id',
  'service:id:cognito:secret-access-key': 'Secret Access Key',
  'service:id:cognito:region': 'Région Cognito',
  'service:id:cognito:pool-id': 'Id du pool Cognito',
  'service:id:cognito:user-attribute-id': 'Attribut utilisateur pour ID',
  'service:id:cognito:user-attribute-id-description': "Attribut Cognito utilisé comme identifiant Ligoj. Par défaut : sub, le principal transmis en mode pré-authentification (ALB X-Amzn-Oidc-Identity). Chaque attribut Cognito est aussi exposé comme attribut personnalisé : service:id:user-display peut en désigner un (mail, preferred_username, nickname, custom:…), avec l'identifiant en repli.",
  'service:id:cognito:access-key-id-description': "Laisser vide (avec la clé secrète) pour utiliser le rôle fourni par l'hôte : rôle de tâche ECS/Fargate ou profil d'instance EC2",
  'service:id:cognito:secret-access-key-description': "Laisser vide (avec la clé d'accès) pour utiliser le rôle fourni par l'hôte : rôle de tâche ECS/Fargate ou profil d'instance EC2",
  'id.cognito.wizard.connection': 'Connexion AWS',
}
