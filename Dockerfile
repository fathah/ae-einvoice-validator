# syntax=docker/dockerfile:1.7
FROM eclipse-temurin:21-jdk-alpine@sha256:0bfc69a4758a86710e5c474032d28400a8bd00874766f9e8b1642ac2fd293159 AS build
WORKDIR /opt/app
ADD --checksum=sha256:b571af282f25d7301059f788b9a149aab8b5cdc14ef3d212dc5425d3dcbb9a97 https://repo.maven.apache.org/maven2/net/sf/saxon/Saxon-HE/12.10/Saxon-HE-12.10.jar /opt/app/lib/Saxon-HE-12.10.jar
ADD --checksum=sha256:1fe4d5b92f708dcdb82dbce12919e0171e6b5ca62c6dca6220483625098feb5f https://repo.maven.apache.org/maven2/org/xmlresolver/xmlresolver/5.3.3/xmlresolver-5.3.3.jar /opt/app/lib/xmlresolver-5.3.3.jar
ADD --checksum=sha256:b0c487ad2f3e558be8d829c916d2458d10aca6a5bafa7a4d0524b70845e48a5c https://repo.maven.apache.org/maven2/org/xmlresolver/xmlresolver/5.3.3/xmlresolver-5.3.3-data.jar /opt/app/lib/xmlresolver-5.3.3-data.jar
COPY src/Validator.java ./src/Validator.java
RUN chmod 0444 /opt/app/lib/*.jar && javac -cp '/opt/app/lib/*' -d /opt/app/classes /opt/app/src/Validator.java

FROM eclipse-temurin:21-jre-alpine@sha256:51ab5e3302e7141ce665ca3ea85e8b5cd648eafbc3c0c90dd79d6537684e4555
# Patch the pinned runtime packages; security scanning remains a release gate.
RUN apk add --no-cache 'libexpat>=2.9.0-r0' 'brotli-libs>=1.2.1-r0'
WORKDIR /opt/app
COPY --from=build /opt/app/classes /opt/app/classes
COPY --from=build /opt/app/lib /opt/app/lib
COPY resources/pint-ae-1.0.4/manifest.json resources/pint-ae-1.0.4/billing-resources.zip resources/pint-ae-1.0.4/ubl21-schemas.zip /opt/app/resources/
USER 65532:65532
EXPOSE 8081
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 CMD wget -q -T 2 -O /dev/null http://127.0.0.1:8081/healthz || exit 1
ENTRYPOINT ["java", "-Xms32m", "-Xmx128m", "-cp", "/opt/app/classes:/opt/app/lib/*", "Validator"]
