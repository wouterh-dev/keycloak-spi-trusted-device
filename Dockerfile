FROM quay.io/keycloak/keycloak:21.1.1

#COPY target/lib/*.jar ./providers/
COPY target/keycloak-spi-trusted-device-*-SNAPSHOT.jar /opt/keycloak/providers/keycloak-spi-trusted-device.jar
