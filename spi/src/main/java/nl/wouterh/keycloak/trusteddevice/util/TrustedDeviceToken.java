package nl.wouterh.keycloak.trusteddevice.util;

import org.keycloak.TokenCategory;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.JsonWebToken;

import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.NewCookie.SameSite;
import jakarta.ws.rs.core.UriBuilder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import nl.wouterh.keycloak.trusteddevice.credential.TrustedDeviceCredentialModel;
import nl.wouterh.keycloak.trusteddevice.credential.TrustedDeviceCredentialProvider;
import nl.wouterh.keycloak.trusteddevice.credential.TrustedDeviceCredentialProviderFactory;

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
    SameSite sameSiteValue = secure ? SameSite.NONE : null;
    NewCookie newCookie = new NewCookie.Builder(COOKIE_NAME)
      .maxAge(maxAge)
      .value(value)
      .path(path)
      .secure(secure)
      .sameSite(sameSiteValue)
      .build();

    session.getContext().getHttpResponse().setCookieIfAbsent(newCookie);
  }

  /**
   * Retrieves the TrustedDeviceToken from the session cookie.
   *
   * @param session The KeycloakSession object.
   * @return The TrustedDeviceToken object if the cookie exists and is valid, otherwise null.
   */
  private static TrustedDeviceToken getCookie(KeycloakSession session) {
    Cookie cookie = session.getContext().getRequestHeaders().getCookies().get(COOKIE_NAME);
    long time = Time.currentTime();

    if (cookie == null) {
      return null;
    }
    
    TrustedDeviceToken decoded = session.tokens().decode(cookie.getValue(), TrustedDeviceToken.class);
    if (decoded != null && (decoded.getExp() == null || decoded.getExp() > time)) {
      return decoded;
    }
    
    return null;
  }

  /**
   * Retrieves the trusted device credential from the cookie.
   *
   * @param session the Keycloak session
   * @param realm the realm model
   * @param user the user model
   * @return the trusted device credential, or null if not found or invalid
   */
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
