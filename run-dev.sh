#!/bin/bash
set -xeuo pipefail
mvn package -DskipTests
docker-compose up --build -d
docker-compose logs --no-log-prefix -f keycloak
