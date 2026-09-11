package com.example.iam.sdk;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.web.client.RestClient;

@AutoConfiguration
@EnableScheduling
@ConditionalOnWebApplication
@EnableConfigurationProperties(IamProperties.class)
@ConditionalOnProperty(prefix = "iam.resource-server", name = "enabled", havingValue = "true", matchIfMissing = true)
@Import(IamSecurityConfiguration.class)
public class IamAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public IamJwksClient iamJwksClient(IamProperties properties) {
        return new IamJwksClient(properties.getIssuer(), properties.getJwks().getCacheTtl());
    }

    @Bean
    @ConditionalOnMissingBean
    public IamTokenClient iamTokenClient(IamProperties properties) {
        return new IamTokenClient(properties.getIssuer());
    }

    @Bean
    @ConditionalOnMissingBean
    public JwksRefreshScheduler jwksRefreshScheduler(IamJwksClient jwksClient) {
        return new JwksRefreshScheduler(jwksClient);
    }

    @Bean
    public RestClient.Builder iamRestClientBuilder() {
        return RestClient.builder();
    }
}
