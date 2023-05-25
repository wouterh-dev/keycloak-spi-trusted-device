package nl.wouterh.keycloak.trusteddevice.compat.kc20;

import java.util.Set;
import org.keycloak.common.util.ServerCookie.SameSiteAttributeValue;
import org.keycloak.services.util.CookieHelper;

public class KC20CookieHelper {

  public static Set<String> getCookieValue(String name) {
    return CookieHelper.getCookieValue(name);
  }

  public static void addCookie(String name, String value, String path, String domain,
      String comment, int maxAge, boolean secure, boolean httpOnly,
      SameSiteAttributeValue sameSite) {
    CookieHelper.addCookie(name, value, path, domain, comment, maxAge, secure, httpOnly, sameSite);
  }
}
