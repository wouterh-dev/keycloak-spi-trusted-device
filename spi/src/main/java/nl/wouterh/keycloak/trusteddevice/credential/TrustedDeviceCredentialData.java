package nl.wouterh.keycloak.trusteddevice.credential;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class TrustedDeviceCredentialData {

  private Long expireTime;

}
