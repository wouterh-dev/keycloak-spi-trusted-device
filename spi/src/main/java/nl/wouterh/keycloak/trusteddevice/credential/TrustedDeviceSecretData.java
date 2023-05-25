package nl.wouterh.keycloak.trusteddevice.credential;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class TrustedDeviceSecretData {

  private String deviceId;
}
