package nl.wouterh.keycloak.trusteddevice.authenticator;

import static nl.wouterh.keycloak.trusteddevice.authenticator.RegisterTrustedDeviceAuthenticatorFactory.CONF_DURATION;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Map;

import org.apache.commons.codec.binary.Hex;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import com.google.common.base.Strings;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import nl.wouterh.keycloak.trusteddevice.credential.TrustedDeviceCredentialModel;
import nl.wouterh.keycloak.trusteddevice.credential.TrustedDeviceCredentialProvider;
import nl.wouterh.keycloak.trusteddevice.credential.TrustedDeviceCredentialProviderFactory;
import nl.wouterh.keycloak.trusteddevice.util.TrustedDeviceToken;
import nl.wouterh.keycloak.trusteddevice.util.UserAgentParser;

public class RegisterTrustedDeviceAuthenticator implements Authenticator {

  private static final SecureRandom secureRandom = new SecureRandom();
  private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd")
      .withZone(ZoneId.of("UTC"));

  private final KeycloakSession session;

  public RegisterTrustedDeviceAuthenticator(KeycloakSession session) {
    this.session = session;
  }

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    UserModel user = context.getUser();
    RealmModel realm = context.getRealm();

    TrustedDeviceCredentialModel credential = TrustedDeviceToken.getCredentialFromCookie(
        context.getSession(), realm, user);

    // Check if the user already has a trusted device
    if (credential != null) {
      context.success();
    } else {
      // Otherwise, show the registration form
      Response form = context.form()
          .setAttribute("trustedDeviceName", UserAgentParser.getDeviceName(session))
          .createForm("trusted-device-register.ftl");
      context.challenge(form);
    }
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    UserModel user = context.getUser();
    RealmModel realm = context.getRealm();

    TrustedDeviceCredentialModel existingCredential = TrustedDeviceToken.getCredentialFromCookie(
        session, context.getRealm(), context.getUser());
    if (existingCredential != null) {
      return;
    }

    Duration duration = null;

    AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
    if (authenticatorConfig != null) {
      Map<String, String> config = authenticatorConfig.getConfig();
      if (config != null && !Strings.isNullOrEmpty(config.get(CONF_DURATION))) {
        duration = Duration.parse(config.get(CONF_DURATION));
      }
    }

    MultivaluedMap<String, String> formParameters = context.getHttpRequest()
        .getDecodedFormParameters();

    boolean trustedDevice = "yes".equals(formParameters.getFirst("trusted-device"));
    String deviceName = formParameters.getFirst("trusted-device-name");

    if (trustedDevice && !Strings.isNullOrEmpty(deviceName)) {
      TrustedDeviceCredentialProvider trustedDeviceCredentialProvider = (TrustedDeviceCredentialProvider) session.getProvider(
          CredentialProvider.class, TrustedDeviceCredentialProviderFactory.PROVIDER_ID);

      // Generate a random 32 byte deviceId
      byte[] bytes = new byte[32];
      secureRandom.nextBytes(bytes);
      String deviceId = Hex.encodeHexString(bytes);

      // Expire the token in configured duration
      Long exp = null;
      String credentialName = deviceName;
      if (duration != null) {
        exp = Time.currentTime() + duration.getSeconds();

        credentialName = String.format("%s (Expires: %s)", deviceName,
            formatter.format(Instant.ofEpochSecond(exp)));
      }

      TrustedDeviceCredentialModel trustedDeviceCredentialModel = TrustedDeviceCredentialModel.create(
          credentialName, deviceId, exp);

      // Remove all expired credentials
      trustedDeviceCredentialProvider.removeExpiredCredentials(realm, user);

      // Add the new credential
      CredentialModel credential = trustedDeviceCredentialProvider.createCredential(realm, user,
          trustedDeviceCredentialModel);

      int cookieExpirationTime = duration != null ? (int) duration.getSeconds() : Integer.MAX_VALUE;

      TrustedDeviceToken token = new TrustedDeviceToken(credential.getId(), deviceId, exp);
      TrustedDeviceToken.addCookie(session, realm, token, cookieExpirationTime);
    }

    context.success();
  }


  @Override
  public boolean requiresUser() {
    return true;
  }

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    return true;
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
  }

  @Override
  public void close() {

  }
}
