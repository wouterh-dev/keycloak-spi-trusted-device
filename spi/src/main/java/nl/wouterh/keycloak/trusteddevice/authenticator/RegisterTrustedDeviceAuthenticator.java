package nl.wouterh.keycloak.trusteddevice.authenticator;

import static nl.wouterh.keycloak.trusteddevice.authenticator.RegisterTrustedDeviceAuthenticatorFactory.CONF_DEVICE_NAME_REQUIRED;
import static nl.wouterh.keycloak.trusteddevice.authenticator.RegisterTrustedDeviceAuthenticatorFactory.CONF_DURATION;

import com.google.common.base.Strings;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import nl.wouterh.keycloak.trusteddevice.credential.TrustedDeviceCredentialModel;
import nl.wouterh.keycloak.trusteddevice.credential.TrustedDeviceCredentialProvider;
import nl.wouterh.keycloak.trusteddevice.credential.TrustedDeviceCredentialProviderFactory;
import nl.wouterh.keycloak.trusteddevice.util.TrustedDeviceToken;
import nl.wouterh.keycloak.trusteddevice.util.UserAgentParser;
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

    if (credential != null) {
      context.success();
    } else {
      Response form = context.form()
          .setAttribute("trustedDeviceName", UserAgentParser.getDeviceName(session))
          .setAttribute("deviceNameRequired", isDeviceNameRequired(context.getAuthenticatorConfig()))
          .createForm("trusted-device-register.ftl");
      context.challenge(form);
    }
  }

  private static boolean isDeviceNameRequired(AuthenticatorConfigModel authenticatorConfig) {
    if (authenticatorConfig == null) {
      return true;
    }
    Map<String, String> config = authenticatorConfig.getConfig();
    if (config == null) {
      return true;
    }
    String value = config.get(CONF_DEVICE_NAME_REQUIRED);
    if (Strings.isNullOrEmpty(value)) {
      return true;
    }
    return Boolean.parseBoolean(value);
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

    boolean deviceNameRequired = isDeviceNameRequired(authenticatorConfig);

    MultivaluedMap<String, String> formParameters = context.getHttpRequest()
        .getDecodedFormParameters();

    boolean trustedDevice = "yes".equals(formParameters.getFirst("trusted-device"));
    String deviceName = formParameters.getFirst("trusted-device-name");

    if (trustedDevice && (!deviceNameRequired || !Strings.isNullOrEmpty(deviceName))) {
      TrustedDeviceCredentialProvider trustedDeviceCredentialProvider = (TrustedDeviceCredentialProvider) session.getProvider(
          CredentialProvider.class, TrustedDeviceCredentialProviderFactory.PROVIDER_ID);

      // Generate a random 32 byte deviceId
      byte[] bytes = new byte[32];
      secureRandom.nextBytes(bytes);
      String deviceId = Hex.encodeHexString(bytes);

      Long exp = null;
      if (duration != null) {
        exp = Time.currentTime() + duration.getSeconds();
      }

      String credentialName = null;
      if (!Strings.isNullOrEmpty(deviceName)) {
        credentialName = exp != null
            ? String.format("%s (Expires: %s)", deviceName,
                formatter.format(Instant.ofEpochSecond(exp)))
            : deviceName;
      }

      Set<String> existingCredentials = user.credentialManager()
          .getStoredCredentialsByTypeStream(TrustedDeviceCredentialModel.TYPE_TWOFACTOR)
          .map(CredentialModel::getUserLabel)
          .collect(Collectors.toSet());

      {
        // Suffix the credentialName with a number to make it unique
        int suffix = 2;
        final String originalCredentialName = credentialName;
        while (existingCredentials.contains(credentialName)) {
          credentialName = originalCredentialName + " " + suffix;
          suffix++;
        }
      }

      TrustedDeviceCredentialModel trustedDeviceCredentialModel = TrustedDeviceCredentialModel.create(
          credentialName, deviceId, exp);

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
