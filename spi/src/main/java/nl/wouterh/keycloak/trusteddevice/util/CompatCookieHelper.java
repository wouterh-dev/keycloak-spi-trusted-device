package nl.wouterh.keycloak.trusteddevice.util;

import java.util.Set;
import nl.wouterh.keycloak.trusteddevice.compat.kc20.KC20CookieHelper;
import org.keycloak.common.util.ServerCookie.SameSiteAttributeValue;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.util.CookieHelper;

public class CompatCookieHelper {

  private enum CompatVersion {
    KC20, KC21
  }

  private static CompatVersion compatVersion;

  public static Set<String> getCookieValue(KeycloakSession session, String name) {
    if (compatVersion == CompatVersion.KC20) {
      return KC20CookieHelper.getCookieValue(name);
    }

    try {
      return CookieHelper.getCookieValue(session, name);
    } catch (NoSuchMethodError e) {
      Set<String> result = KC20CookieHelper.getCookieValue(name);
      compatVersion = CompatVersion.KC20;
      return result;
    }
  }

  public static void addCookie(String name, String value, String path, String domain,
      String comment, int maxAge, boolean secure, boolean httpOnly, SameSiteAttributeValue sameSite,
      KeycloakSession session) {
    if (compatVersion == CompatVersion.KC20) {
      KC20CookieHelper.addCookie(name, value, path, domain, comment, maxAge, secure,
          httpOnly, sameSite);
      return;
    }

    try {
      CookieHelper.addCookie(name, value, path, domain, comment, maxAge, secure, httpOnly, sameSite,
          session);
    } catch (NoSuchMethodError e) {
      KC20CookieHelper.addCookie(name, value, path, domain, comment, maxAge, secure,
          httpOnly, sameSite);
      compatVersion = CompatVersion.KC20;
    }
  }
}
