FROM eclipse-temurin:21-jre
WORKDIR /app
COPY iam-authorization-server/target/iam-authorization-server-0.1.0-SNAPSHOT-exec.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
