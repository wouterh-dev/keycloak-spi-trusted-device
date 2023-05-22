package nl.wouterh.keycloak.trusteddevice.authenticator;

import com.google.auto.service.AutoService;
import java.util.Arrays;
import java.util.List;
import nl.wouterh.keycloak.trusteddevice.credential.TrustedDeviceCredentialModel;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

@AutoService(AuthenticatorFactory.class)
public class RegisterTrustedDeviceAuthenticatorFactory implements AuthenticatorFactory {

  public static final String CONF_DURATION = "duration";

  public static final String PROVIDER_ID = "trusted-device-authenticator";

  @Override
  public String getDisplayType() {
    return "Register Trusted Device";
  }

  @Override
  public String getReferenceCategory() {
    return TrustedDeviceCredentialModel.TYPE_TWOFACTOR;
  }

  @Override
  public boolean isConfigurable() {
    return true;
  }

  @Override
  public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
    return REQUIREMENT_CHOICES;
  }

  @Override
  public boolean isUserSetupAllowed() {
    return true;
  }

  @Override
  public String getHelpText() {
    return "Prompts the user if they want to trust their device. Use 'Condition - Credential Configured' to check if the device is trusted.";
  }


  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    ProviderConfigProperty duration = new ProviderConfigProperty();
    duration.setType(ProviderConfigProperty.STRING_TYPE);
    duration.setName(CONF_DURATION);
    duration.setLabel("Trust duration");
    duration.setDefaultValue("P90d");
    duration.setHelpText(
        "Duration the device will be trusted. Input format is a Java Duration, for example P365d or PT24h");

    return Arrays.asList(duration);
  }

  @Override
  public Authenticator create(KeycloakSession session) {
    return new RegisterTrustedDeviceAuthenticator(session);
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
