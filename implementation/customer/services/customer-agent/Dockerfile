FROM eclipse-temurin:24-jre
WORKDIR /application

# libsodium cho backend NIPoK native (customer.agent.nipok.group=libsodium) — agent PROVE nhanh 2.8×.
# Thiếu lib này thì factory tự fallback elisabeth (pure-Java) nên image vẫn chạy.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libsodium23 \
 && rm -rf /var/lib/apt/lists/*

COPY build/libs/customer-agent-1.0.0-SNAPSHOT.jar app.jar
EXPOSE 8080

# --enable-native-access=ALL-UNNAMED: cần cho Panama FFM gọi libsodium (LibsodiumEd25519Group) mà
# không bị JDK 24 chặn/cảnh báo. Vô hại khi group=elisabeth (không gọi native).
ENTRYPOINT ["java", "--enable-native-access=ALL-UNNAMED", "-jar", "app.jar"]
