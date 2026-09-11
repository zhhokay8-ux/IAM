package com.example.iam.gateway;

import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.resourceserver.jwt.IssuerValidator;
import com.example.iam.token.signing.JwtKeyResolver;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.util.AntPathMatcher;

public class JwtGatewayFilter implements IamGatewayFilter {

    public static final String SUBJECT_ATTRIBUTE = "iam.gateway.sub";

    private final JwtKeyResolver keyResolver;
    private final IssuerValidator issuerValidator;
    private final Clock clock;
    private final Duration clockSkew;
    private final String[] permitAll;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    public JwtGatewayFilter(
            JwtKeyResolver keyResolver,
            String issuer,
            Duration clockSkew,
            String[] permitAll) {
        this(keyResolver, new IssuerValidator(issuer), Clock.systemUTC(), clockSkew, permitAll);
    }

    JwtGatewayFilter(
            JwtKeyResolver keyResolver,
            IssuerValidator issuerValidator,
            Clock clock,
            Duration clockSkew,
            String[] permitAll) {
        this.keyResolver = keyResolver;
        this.issuerValidator = issuerValidator;
        this.clock = clock == null ? Clock.systemUTC() : clock;
        this.clockSkew = clockSkew == null ? Duration.ofSeconds(30) : clockSkew;
        this.permitAll = permitAll == null ? new String[0] : permitAll;
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 30;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        if (HttpMethod.OPTIONS.matches(httpRequest.getMethod()) || permitted(httpRequest.getRequestURI())) {
            chain.doFilter(request, response);
            return;
        }
        try {
            String header = httpRequest.getHeader(HttpHeaders.AUTHORIZATION);
            if (header == null || header.isBlank() || !header.regionMatches(true, 0, "Bearer ", 0, 7)) {
                throw new IamException(IamErrorCode.UNAUTHORIZED, "access token is required");
            }
            JWTClaimsSet claims = validateFirstPass(header.substring(7).trim());
            httpRequest.setAttribute(SUBJECT_ATTRIBUTE, claims.getSubject());
            chain.doFilter(request, response);
        } catch (IamException ex) {
            HttpServletResponse httpResponse = (HttpServletResponse) response;
            httpResponse.setStatus(ex.getErrorCode().getHttpStatus());
            httpResponse.setContentType("application/json");
            httpResponse.getWriter()
                    .write("{\"code\":\"" + ex.getErrorCode().getCode() + "\",\"message\":\"" + ex.getMessage() + "\"}");
        }
    }

    JWTClaimsSet validateFirstPass(String token) {
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            if (!JWSAlgorithm.RS256.equals(jwt.getHeader().getAlgorithm())) {
                throw new IamException(IamErrorCode.INVALID_JWT, "JWT alg must be RS256");
            }
            String kid = jwt.getHeader().getKeyID();
            RSAPublicKey publicKey = keyResolver.resolvePublicKey(kid);
            if (!jwt.verify(new RSASSAVerifier(publicKey))) {
                throw new IamException(IamErrorCode.INVALID_JWT_SIGNATURE, "JWT signature is invalid");
            }
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            issuerValidator.validate(claims.getIssuer());
            Instant now = clock.instant();
            Date exp = claims.getExpirationTime();
            if (exp == null || now.minus(clockSkew).isAfter(exp.toInstant())) {
                throw new IamException(IamErrorCode.JWT_EXPIRED, "JWT expired");
            }
            Date nbf = claims.getNotBeforeTime();
            if (nbf != null && now.plus(clockSkew).isBefore(nbf.toInstant())) {
                throw new IamException(IamErrorCode.JWT_NOT_BEFORE, "JWT is not yet valid");
            }
            return claims;
        } catch (IamException ex) {
            throw ex;
        } catch (ParseException | JOSEException ex) {
            throw new IamException(IamErrorCode.INVALID_JWT, "JWT is invalid", ex);
        }
    }

    private boolean permitted(String path) {
        for (String pattern : permitAll) {
            if (pattern != null && !pattern.isBlank() && pathMatcher.match(pattern, path)) {
                return true;
            }
        }
        return false;
    }
}
