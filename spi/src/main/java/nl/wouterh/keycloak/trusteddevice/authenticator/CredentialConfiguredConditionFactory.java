package nl.wouterh.keycloak.trusteddevice.authenticator;

import com.google.auto.service.AutoService;
import java.util.Arrays;
import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

@AutoService(AuthenticatorFactory.class)
public class CredentialConfiguredConditionFactory implements
    ConditionalAuthenticatorFactory {

  public static final String CONF_NEGATE = "negate";
  public static final String CONF_AUTH = "auth";
  public static final String PROVIDER_ID = "configured-credential-condition";

  @Override
  public String getDisplayType() {
    return "Condition - Credential Configured";
  }

  @Override
  public ConditionalAuthenticator getSingleton() {
    return CredentialConfiguredCondition.SINGLETON;
  }

  @Override
  public boolean isConfigurable() {
    return true;
  }

  private static final Requirement[] REQUIREMENT_CHOICES = {
      Requirement.REQUIRED,
      Requirement.DISABLED
  };

  @Override
  public Requirement[] getRequirementChoices() {
    return REQUIREMENT_CHOICES;
  }

  @Override
  public boolean isUserSetupAllowed() {
    return true;
  }

  @Override
  public String getHelpText() {
    return "Flow is only executed if device is trusted.";
  }


  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    ProviderConfigProperty authTypes = new ProviderConfigProperty();
    authTypes.setType(ProviderConfigProperty.MULTIVALUED_STRING_TYPE);
    authTypes.setName(CONF_AUTH);
    authTypes.setLabel("Authenticator types");
    authTypes.setHelpText(
        "Condition matches if one of the user has one of the authenticator types configured");

    ProviderConfigProperty negateOutput = new ProviderConfigProperty();
    negateOutput.setType(ProviderConfigProperty.BOOLEAN_TYPE);
    negateOutput.setName(CONF_NEGATE);
    negateOutput.setLabel("Negate output");
    negateOutput.setDefaultValue(Boolean.toString(false));
    negateOutput.setHelpText(
        "Apply a NOT to the check result. When this is true, then the condition will evaluate to true just if user does NOT have any of the authenticators configured. When this is false, the condition will evaluate to true if user has any of the configured authenticators");

    return Arrays.asList(authTypes, negateOutput);
  }

  @Override
  public void init(Config.Scope config) {

  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {
  }

  @Override
  public void close() {

  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }
}
