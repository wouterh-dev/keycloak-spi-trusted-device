package nl.wouterh.keycloak.trusteddevice.util;

import jakarta.ws.rs.core.HttpHeaders;
import org.keycloak.models.KeycloakSession;
import ua_parser.Client;
import ua_parser.Parser;

public class UserAgentParser {

  private static Parser parser;

  public static synchronized Parser getParser() {
    if (parser == null) {
      parser = new Parser();
    }

    return parser;
  }

  public static String getDeviceName(KeycloakSession session) {
    String userAgent = session.getContext().getRequestHeaders()
        .getHeaderString(HttpHeaders.USER_AGENT);

    if (userAgent == null) {
      return null;
    }

    if (userAgent.length() > 512) {
      return null;
    }

    Client parsed = getParser().parse(userAgent);
    return parsed.userAgent.family + " on " + parsed.os.family;
  }

}
