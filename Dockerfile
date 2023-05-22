FROM quay.io/keycloak/keycloak:20.0.3

#COPY target/lib/*.jar ./providers/
COPY target/keycloak-spi-trusted-device-*-SNAPSHOT.jar /opt/keycloak/providers/keycloak-spi-trusted-device.jar
