package com.example.iam.authorizationserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication(scanBasePackages = "com.example.iam")
@EntityScan(basePackages = "com.example.iam")
@EnableJpaRepositories(basePackages = "com.example.iam")
public class IamAuthorizationServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(IamAuthorizationServerApplication.class, args);
    }
}
