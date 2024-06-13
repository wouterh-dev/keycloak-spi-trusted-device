package nl.wouterh.keycloak.trusteddevice;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.keycloak.TokenCategory;
import org.keycloak.common.util.Time;

import nl.wouterh.keycloak.trusteddevice.util.TrustedDeviceToken;

public class TrustedDeviceTokenTest {

    @Test
    public void testCreateTrustedDeviceToken() {
        TrustedDeviceToken token = new TrustedDeviceToken("secret-id", "secret", (long) 10000000);

        // Check mappers work correctly
        assertEquals("secret-id", token.getId());
        assertEquals("secret", token.getSecret());
        assertEquals(10000000, token.getExp());
        assertTrue(token.getIat() >= Time.currentTime(),
                "iat should be set to current time or later to avoid time drift issues in test");

        assertEquals(TokenCategory.INTERNAL, token.getCategory());
    }

}
