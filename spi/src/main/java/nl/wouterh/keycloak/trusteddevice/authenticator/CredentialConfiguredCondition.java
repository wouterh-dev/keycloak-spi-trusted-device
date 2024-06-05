package nl.wouterh.keycloak.trusteddevice.authenticator;

import java.util.Arrays;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

@JBossLog
public class CredentialConfiguredCondition implements ConditionalAuthenticator {

  public static final CredentialConfiguredCondition SINGLETON = new CredentialConfiguredCondition();

  @Override
  public boolean matchCondition(AuthenticationFlowContext context) {
    AuthenticatorConfigModel authConfig = context.getAuthenticatorConfig();

    if (authConfig != null && authConfig.getConfig() != null) {
      boolean negateOutput = Boolean.parseBoolean(
          authConfig.getConfig().get(CredentialConfiguredConditionFactory.CONF_NEGATE));
      boolean hasAuthenticator = false;

      String authenticatorNamesStr = authConfig.getConfig()
          .get(CredentialConfiguredConditionFactory.CONF_AUTH);
      if (authenticatorNamesStr != null) {
        String[] authenticatorNames = Constants.CFG_DELIMITER_PATTERN.split(
            authenticatorNamesStr);
        hasAuthenticator = Arrays.stream(authenticatorNames)
            .anyMatch(authenticator -> context.getUser().credentialManager()
                .isConfiguredFor(authenticator));
      }

      return hasAuthenticator != negateOutput;
    }

    return false;
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    // Not used
  }

  @Override
  public boolean requiresUser() {
    return true;
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    // Not used
  }

  @Override
  public void close() {
    // Does nothing
  }
}
