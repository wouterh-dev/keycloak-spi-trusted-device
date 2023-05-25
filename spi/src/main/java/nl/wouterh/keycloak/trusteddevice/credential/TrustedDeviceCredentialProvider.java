package nl.wouterh.keycloak.trusteddevice.credential;

import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;
import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.CredentialTypeMetadata;
import org.keycloak.credential.CredentialTypeMetadataContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public class TrustedDeviceCredentialProvider implements
    CredentialProvider<TrustedDeviceCredentialModel> {

  private KeycloakSession session;

  public TrustedDeviceCredentialProvider(KeycloakSession session) {
    this.session = session;
  }

  @Override
  public String getType() {
    return TrustedDeviceCredentialModel.TYPE_TWOFACTOR;
  }

  public List<TrustedDeviceCredentialModel> removeExpiredCredentials(RealmModel realm,
      UserModel user) {
    // Remove all other expired credentials
    List<TrustedDeviceCredentialModel> credentials = user.credentialManager()
        .getStoredCredentialsByTypeStream(TrustedDeviceCredentialModel.TYPE_TWOFACTOR)
        .map(TrustedDeviceCredentialModel::createFromCredentialModel)
        .collect(Collectors.toList());

    long now = Time.currentTime();
    Iterator<TrustedDeviceCredentialModel> it = credentials.iterator();
    while (it.hasNext()) {
      TrustedDeviceCredentialModel credential = it.next();
      if (credential.getExpireTime() != null && credential.getExpireTime() < now) {
        deleteCredential(realm, user, credential.getId());
        it.remove();
      }
    }

    return credentials;
  }

  public TrustedDeviceCredentialModel getActiveCredentialById(RealmModel realm, UserModel user,
      String id) {
    List<TrustedDeviceCredentialModel> credentials = removeExpiredCredentials(realm, user);
    for (TrustedDeviceCredentialModel credential : credentials) {
      if (id.equals(credential.getId())) {
        return credential;
      }
    }

    return null;
  }

  @Override
  public CredentialModel createCredential(RealmModel realm, UserModel user,
      TrustedDeviceCredentialModel credentialModel) {
    if (credentialModel.getCreatedDate() == null) {
      credentialModel.setCreatedDate(Time.currentTimeMillis());
    }

    return user.credentialManager().createStoredCredential(credentialModel);
  }

  @Override
  public boolean deleteCredential(RealmModel realm, UserModel user, String credentialId) {
    return user.credentialManager().removeStoredCredentialById(credentialId);
  }

  @Override
  public TrustedDeviceCredentialModel getCredentialFromModel(CredentialModel model) {
    return TrustedDeviceCredentialModel.createFromCredentialModel(model);
  }

  @Override
  public CredentialTypeMetadata getCredentialTypeMetadata(
      CredentialTypeMetadataContext metadataContext) {
    return CredentialTypeMetadata.builder()
        .type(getType())
        .category(CredentialTypeMetadata.Category.TWO_FACTOR)
        .displayName("trusted-device-display-name")
        .helpText("trusted-device-help-text")
        .iconCssClass("kcAuthenticatorWebAuthnClass")
        .removeable(true)
        .build(session);
  }
}
