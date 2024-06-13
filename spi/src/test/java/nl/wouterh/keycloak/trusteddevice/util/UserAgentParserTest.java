package nl.wouterh.keycloak.trusteddevice.util;

import org.junit.jupiter.api.Test;

import jakarta.ws.rs.core.HttpHeaders;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakContext;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class UserAgentParserTest {

    @Test
    public void testGetDeviceName() {

        // Mock the KeycloakSession
        KeycloakSession session = mock(KeycloakSession.class);
        HttpHeaders headers = mock(HttpHeaders.class);
        KeycloakContext context = mock(KeycloakContext.class);

        // Mock the KeycloakSession to return the mocked HttpHeaders
        when(session.getContext()).thenReturn(context);
        when(session.getContext().getRequestHeaders()).thenReturn(headers);

        // Mock the User-Agent header
        when(headers.getHeaderString(HttpHeaders.USER_AGENT))
            .thenReturn("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3");

        // Call the method under test
        String deviceName = UserAgentParser.getDeviceName(session);

        // Verify the result
        assertEquals("Chrome on Windows", deviceName);
    } 
}