FROM eclipse-temurin:24_36-jre-noble AS builder
WORKDIR /extracted
ADD ./build/libs/*.jar app.jar
RUN java -Djarmode=layertools -jar app.jar extract

FROM eclipse-temurin:24_36-jre-noble
WORKDIR /application

# Native libsodium needed by the libsodium-lazysodium-jna and libsodium-panama-ffm strategies.
# Adds ~1 MB; harmless for the other 5 strategies (they don't dlopen it).
RUN apt-get update \
 && apt-get install -y --no-install-recommends libsodium23 \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /extracted/dependencies/ ./
COPY --from=builder /extracted/spring-boot-loader/ ./
COPY --from=builder /extracted/snapshot-dependencies/ ./
COPY --from=builder /extracted//application/ ./

EXPOSE 80

# --enable-native-access=ALL-UNNAMED: required so Conscrypt 2.6-alpha (the DEFAULT provider)
# can load its native libconscrypt_openjdk_jni.so without a JDK 24 restricted-method warning.
# Also required when APP_ED25519_PROVIDER ∈ {libsodium-lazysodium-jna, libsodium-panama-ffm}.
# Harmless when the configured provider is pure-Java (jca-sunec / tink / bc-*).
ENTRYPOINT ["java", "--enable-native-access=ALL-UNNAMED", "org.springframework.boot.loader.launch.JarLauncher"]