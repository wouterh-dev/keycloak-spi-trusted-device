package nl.wouterh.keycloak.trusteddevice.util;

import jakarta.ws.rs.core.UriBuilder;
import java.util.Set;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import nl.wouterh.keycloak.trusteddevice.credential.TrustedDeviceCredentialModel;
import nl.wouterh.keycloak.trusteddevice.credential.TrustedDeviceCredentialProvider;
import nl.wouterh.keycloak.trusteddevice.credential.TrustedDeviceCredentialProviderFactory;
import org.keycloak.TokenCategory;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.util.ServerCookie;
import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.util.CookieHelper;

@Getter
@Setter
@NoArgsConstructor
public class TrustedDeviceToken extends JsonWebToken {

  public static final String COOKIE_NAME = "KEYCLOAK_TRUSTED_DEVICE";

  public static void addCookie(KeycloakSession session, RealmModel realm, TrustedDeviceToken value,
      int maxAge) {
    addCookie(session, realm, session.tokens().encode(value), maxAge);
  }

  private static void addCookie(KeycloakSession session, RealmModel realm, String value,
      int maxAge) {
    UriBuilder baseUriBuilder = session.getContext().getUri().getBaseUriBuilder();
    String path = baseUriBuilder.path("realms").path(realm.getName()).path("/").build().getPath();

    ClientConnection connection = session.getContext().getConnection();
    boolean secure = realm.getSslRequired().isRequired(connection);

    ServerCookie.SameSiteAttributeValue sameSiteValue =
        secure ? ServerCookie.SameSiteAttributeValue.NONE : null;
    CookieHelper.addCookie(
        COOKIE_NAME,
        value,
        path,
        null,
        null,
        maxAge,
        secure,
        true,
        sameSiteValue,
        session
    );
  }

  public static TrustedDeviceToken getCookie(KeycloakSession session) {
    Set<String> cookieValues = CookieHelper.getCookieValue(session, COOKIE_NAME);
    long time = Time.currentTime();

    for (String cookieValue : cookieValues) {
      TrustedDeviceToken decoded = session.tokens().decode(cookieValue, TrustedDeviceToken.class);
      if (decoded != null && (decoded.getExp() == null || decoded.getExp() > time)) {
        return decoded;
      }
    }

    return null;
  }

  public static TrustedDeviceCredentialModel getCredentialFromCookie(KeycloakSession session,
      RealmModel realm, UserModel user) {
    TrustedDeviceToken deviceToken = getCookie(session);
    TrustedDeviceCredentialProvider trustedDeviceCredentialProvider = (TrustedDeviceCredentialProvider) session
        .getProvider(CredentialProvider.class, TrustedDeviceCredentialProviderFactory.PROVIDER_ID);
    if (deviceToken == null) {
      return null;
    }

    TrustedDeviceCredentialModel credential = trustedDeviceCredentialProvider.getActiveCredentialById(
        realm, user, deviceToken.getId());
    if (credential == null || !deviceToken.getSecret().equals(credential.getDeviceId())) {
      return null;
    }

    return credential;
  }

  public TrustedDeviceToken(String id, String secret, Long exp) {
    this.id = id;
    this.secret = secret;
    iat((long) Time.currentTime());
    exp(exp);
  }

  @Override
  public TokenCategory getCategory() {
    return TokenCategory.INTERNAL;
  }

  private String id;

  private String secret;
}
