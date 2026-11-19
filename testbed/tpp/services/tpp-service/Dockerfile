FROM eclipse-temurin:24-jre
WORKDIR /application
COPY build/libs/tpp-service-1.0.0-SNAPSHOT.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
