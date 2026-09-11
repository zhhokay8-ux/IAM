package com.example.iam.resourceserver.security;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.resourceserver.jwt.JtiRevocationStore;
import com.example.iam.resourceserver.jwt.JtiValidator;
import com.example.iam.resourceserver.jwt.AudienceValidator;
import com.example.iam.resourceserver.jwt.IssuerValidator;
import com.example.iam.resourceserver.jwt.JwtTokenValidator;
import com.example.iam.resourceserver.jwt.RoleValidator;
import com.example.iam.resourceserver.jwt.ScopeValidator;
import com.example.iam.token.redis.RevokedJtiRepository;
import com.example.iam.token.signing.JwtKeyResolver;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@EnableWebSecurity
@ConditionalOnProperty(prefix = "iam.resource-server", name = "enabled", havingValue = "true")
public class JwtSecurityConfig implements WebMvcConfigurer {

    private final JwtTokenValidator jwtTokenValidator;
    private final IamJwtAuthenticationConverter authenticationConverter;
    private final ScopeValidator scopeValidator;
    private final RoleValidator roleValidator;

    private final String[] permitAllPatterns;

    public JwtSecurityConfig(
            JwtKeyResolver keyResolver,
            ObjectProvider<RevokedJtiRepository> revokedJtiRepository,
            @Value("${iam.resource-server.issuer}") String issuer,
            @Value("${iam.resource-server.audience}") String audience,
            @Value("${iam.resource-server.jti-revocation-enabled:false}") boolean jtiRevocationEnabled,
            @Value("${iam.resource-server.clock-skew:30s}") Duration clockSkew,
            @Value("${iam.resource-server.permit-all:}") String[] permitAllPatterns) {
        this.permitAllPatterns = permitAllPatterns == null ? new String[0] : permitAllPatterns;
        this.scopeValidator = new ScopeValidator();
        this.roleValidator = new RoleValidator();
        JtiRevocationStore store = jti -> {
            RevokedJtiRepository repository = revokedJtiRepository.getIfAvailable();
            return repository != null && repository.isRevoked(jti);
        };
        this.jwtTokenValidator = new JwtTokenValidator(
                keyResolver,
                new IssuerValidator(issuer),
                new AudienceValidator(audience),
                scopeValidator,
                roleValidator,
                new JtiValidator(jtiRevocationEnabled, store),
                Clock.systemUTC(),
                clockSkew);
        this.authenticationConverter = new IamJwtAuthenticationConverter(jwtTokenValidator);
    }

    @Bean
    public JwtTokenValidator jwtTokenValidator() {
        return jwtTokenValidator;
    }

    @Bean
    public SecurityFilterChain resourceServerSecurityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> {
                    if (permitAllPatterns.length > 0 && !(permitAllPatterns.length == 1 && permitAllPatterns[0].isBlank())) {
                        auth.requestMatchers(permitAllPatterns).permitAll();
                    }
                    auth.anyRequest().authenticated();
                })
                .exceptionHandling(ex -> ex.authenticationEntryPoint((request, response, exception) -> {
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"code\":\"IAM-4010\",\"message\":\"Unauthorized\"}");
                }))
                .addFilterBefore(new BearerJwtAuthenticationFilter(authenticationConverter), UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(new UserContextAuthenticationFilter(), BearerJwtAuthenticationFilter.class);
        return http.build();
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new RequireScopeRoleInterceptor(scopeValidator, roleValidator));
    }

    static final class BearerJwtAuthenticationFilter extends OncePerRequestFilter {

        private final IamJwtAuthenticationConverter converter;

        BearerJwtAuthenticationFilter(IamJwtAuthenticationConverter converter) {
            this.converter = converter;
        }

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
                throws ServletException, IOException {
            String header = request.getHeader(HttpHeaders.AUTHORIZATION);
            if (header == null || header.isBlank()) {
                filterChain.doFilter(request, response);
                return;
            }
            try {
                if (!header.regionMatches(true, 0, "Bearer ", 0, 7)) {
                    throw new IamException(IamErrorCode.UNAUTHORIZED, "Authorization scheme must be Bearer");
                }
                String token = header.substring(7).trim();
                SecurityContextHolder.getContext().setAuthentication(converter.convert(token));
                filterChain.doFilter(request, response);
            } catch (IamException ex) {
                SecurityContextHolder.clearContext();
                int status = ex.getErrorCode().getHttpStatus();
                response.setStatus(status == 403 ? 403 : HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType("application/json");
                response.getWriter()
                        .write("{\"code\":\"" + ex.getErrorCode().getCode() + "\",\"message\":\"" + ex.getMessage() + "\"}");
            }
        }
    }
}
