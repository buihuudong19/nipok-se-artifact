FROM eclipse-temurin:24-jre
WORKDIR /application

# libsodium for the native NIPoK backend (customer.agent.nipok.group=libsodium) - agent PROVE 2.8× faster.
# Without this library the factory falls back to elisabeth (pure Java), so the image still runs.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libsodium23 \
 && rm -rf /var/lib/apt/lists/*

COPY build/libs/customer-agent-1.0.0-SNAPSHOT.jar app.jar
EXPOSE 8080

# --enable-native-access=ALL-UNNAMED: needed for Panama FFM calls to libsodium (LibsodiumEd25519Group) without
# being blocked or warned by JDK 24. Harmless with group=elisabeth (no native call).
ENTRYPOINT ["java", "--enable-native-access=ALL-UNNAMED", "-jar", "app.jar"]
