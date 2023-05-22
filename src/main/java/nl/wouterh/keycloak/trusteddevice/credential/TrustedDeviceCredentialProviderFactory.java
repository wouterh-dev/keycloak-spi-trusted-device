package nl.wouterh.keycloak.trusteddevice.credential;

import com.google.auto.service.AutoService;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.CredentialProviderFactory;
import org.keycloak.models.KeycloakSession;

@AutoService(CredentialProviderFactory.class)
public class TrustedDeviceCredentialProviderFactory implements
    CredentialProviderFactory<TrustedDeviceCredentialProvider> {

  public static final String PROVIDER_ID = "trusted-device";

  @Override
  public CredentialProvider<TrustedDeviceCredentialModel> create(KeycloakSession session) {
    return new TrustedDeviceCredentialProvider(session);
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }
}
