package nl.wouterh.keycloak.trusteddevice.authenticator;

import com.google.auto.service.AutoService;
import java.util.Arrays;
import java.util.List;
import nl.wouterh.keycloak.trusteddevice.credential.TrustedDeviceCredentialModel;
import org.keycloak.Config;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

@AutoService(AuthenticatorFactory.class)
public class TrustedDeviceConditionFactory implements
    ConditionalAuthenticatorFactory {

  public static final String CONF_NEGATE = "negate";
  public static final String PROVIDER_ID = "trusted-device-condition";

  @Override
  public String getDisplayType() {
    return "Condition - Device Trusted";
  }

  @Override
  public String getReferenceCategory() {
    return TrustedDeviceCredentialModel.TYPE_TWOFACTOR;
  }

  @Override
  public ConditionalAuthenticator getSingleton() {
    return TrustedDeviceCondition.SINGLETON;
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
    ProviderConfigProperty negateOutput = new ProviderConfigProperty();
    negateOutput.setType(ProviderConfigProperty.BOOLEAN_TYPE);
    negateOutput.setName(CONF_NEGATE);
    negateOutput.setLabel("Negate output");
    negateOutput.setDefaultValue("true");
    negateOutput.setHelpText(
        "Apply a NOT to the check result. When this is true, then the condition will evaluate to true just if user does NOT have a trusted device. When this is false, the condition will evaluate to true just if user has a trusted device");

    return Arrays.asList(negateOutput);
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
