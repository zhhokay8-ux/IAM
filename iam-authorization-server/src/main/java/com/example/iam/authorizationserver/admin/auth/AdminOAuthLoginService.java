package com.example.iam.authorizationserver.admin.auth;

import com.example.iam.admin.config.IamAdminProperties;
import com.example.iam.audit.AuditEvent;
import com.example.iam.audit.IamAuditService;
import com.example.iam.authorizationserver.oauth.token.TokenAuthenticationService;
import com.example.iam.authorizationserver.oauth.token.TokenRequest;
import com.example.iam.authorizationserver.oauth.token.TokenResponse;
import com.example.iam.authorizationserver.oauth.token.TokenService;
import com.example.iam.authorizationserver.oauth.revoke.TokenRevocationService;
import com.example.iam.authorizationserver.sso.SsoCookieService;
import com.example.iam.clientregistry.entity.IamClientEntity;
import com.example.iam.clientregistry.validation.IamRedirectUriValidator;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.common.util.IdGenerator;
import com.example.iam.session.IamSession;
import com.example.iam.session.IamSessionService;
import com.example.iam.token.oauth.PkceService;
import com.example.iam.token.signing.JwtSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URI;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

@Service
public class AdminOAuthLoginService {

    private static final Logger log = LoggerFactory.getLogger(AdminOAuthLoginService.class);
    private static final SecureRandom RANDOM = new SecureRandom();

    private final IamAdminProperties properties;
    private final IamRedirectUriValidator redirectUriValidator;
    private final PkceService pkceService;
    private final AdminOAuthPendingRepository pendingRepository;
    private final TokenAuthenticationService tokenAuthenticationService;
    private final TokenService tokenService;
    private final TokenRevocationService tokenRevocationService;
    private final JwtSigner jwtSigner;
    private final IamSessionService sessionService;
    private final SsoCookieService cookieService;
    private final IamAuditService auditService;

    public AdminOAuthLoginService(
            IamAdminProperties properties,
            IamRedirectUriValidator redirectUriValidator,
            PkceService pkceService,
            AdminOAuthPendingRepository pendingRepository,
            TokenAuthenticationService tokenAuthenticationService,
            TokenService tokenService,
            TokenRevocationService tokenRevocationService,
            JwtSigner jwtSigner,
            IamSessionService sessionService,
            SsoCookieService cookieService,
            IamAuditService auditService) {
        this.properties = properties;
        this.redirectUriValidator = redirectUriValidator;
        this.pkceService = pkceService;
        this.pendingRepository = pendingRepository;
        this.tokenAuthenticationService = tokenAuthenticationService;
        this.tokenService = tokenService;
        this.tokenRevocationService = tokenRevocationService;
        this.jwtSigner = jwtSigner;
        this.sessionService = sessionService;
        this.cookieService = cookieService;
        this.auditService = auditService;
    }

    public URI startLogin() {
        IamAdminProperties.OAuth oauth = properties.getOauth();
        redirectUriValidator.validateSyntax(oauth.getRedirectUri());
        String state = IdGenerator.next();
        String nonce = IdGenerator.next();
        String verifier = randomVerifier();
        String challenge = pkceService.challengeS256(verifier);
        pendingRepository.save(new AdminOAuthPending(
                state, nonce, verifier, oauth.getRedirectUri(), oauth.getClientId()));
        return UriComponentsBuilder.fromPath("/oauth2/authorize")
                .queryParam("client_id", oauth.getClientId())
                .queryParam("redirect_uri", oauth.getRedirectUri())
                .queryParam("response_type", "code")
                .queryParam("scope", oauth.getScope())
                .queryParam("state", state)
                .queryParam("nonce", nonce)
                .queryParam("code_challenge", challenge)
                .queryParam("code_challenge_method", PkceService.S256)
                .encode()
                .build()
                .toUri();
    }

    public URI completeCallback(
            String code,
            String state,
            String error,
            HttpServletRequest request,
            HttpServletResponse response) {
        if (StringUtils.hasText(error)) {
            auditService.failure(AuditEvent.LOGIN_FAILURE, null, properties.getOauth().getClientId(), error);
            throw new IamException(IamErrorCode.UNAUTHORIZED, "Admin OAuth authorization was denied");
        }
        AdminOAuthPending pending = pendingRepository
                .consumePending(state)
                .orElseThrow(() -> new IamException(IamErrorCode.UNAUTHORIZED, "Admin OAuth state is invalid"));
        if (!pending.redirectUri().equals(properties.getOauth().getRedirectUri())
                || !pending.clientId().equals(properties.getOauth().getClientId())) {
            throw new IamException(IamErrorCode.UNAUTHORIZED, "Admin OAuth pending request is invalid");
        }
        if (!StringUtils.hasText(code)) {
            throw new IamException(IamErrorCode.UNAUTHORIZED, "authorization code is required");
        }
        IamAdminProperties.OAuth oauth = properties.getOauth();
        if (!StringUtils.hasText(oauth.getClientSecret())) {
            throw new IamException(IamErrorCode.UNAUTHORIZED, "Admin BFF client_secret is not configured");
        }
        IamClientEntity client = tokenAuthenticationService.authenticate(oauth.getClientId(), oauth.getClientSecret());
        TokenResponse tokens = tokenService.issue(
                new TokenRequest(
                        "authorization_code",
                        code,
                        pending.redirectUri(),
                        pending.codeVerifier(),
                        null,
                        oauth.getScope(),
                        null,
                        oauth.getClientId(),
                        oauth.getClientSecret()),
                client);
        JWTClaimsSet idClaims = verifyIdToken(tokens.idToken(), pending.nonce(), oauth.getClientId());
        String subject = idClaims.getSubject();
        bindOrCreateSession(request, response, subject, oauth.getClientId());
        discardTokens(tokens);
        auditService.success(AuditEvent.ADMIN_AUTH_SUCCESS, subject, oauth.getClientId(), "admin_oauth_bff");
        return URI.create(oauth.getPostLoginUri());
    }

    private JWTClaimsSet verifyIdToken(String idToken, String expectedNonce, String clientId) {
        if (!StringUtils.hasText(idToken)) {
            throw new IamException(IamErrorCode.UNAUTHORIZED, "id_token is required for admin login");
        }
        SignedJWT jwt;
        try {
            jwt = jwtSigner.verify(idToken);
        } catch (IamException ex) {
            throw new IamException(IamErrorCode.UNAUTHORIZED, "id_token is invalid");
        }
        try {
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            if (expectedNonce == null || !expectedNonce.equals(claims.getStringClaim("nonce"))) {
                throw new IamException(IamErrorCode.UNAUTHORIZED, "id_token nonce mismatch");
            }
            if (claims.getAudience() == null || !claims.getAudience().contains(clientId)) {
                throw new IamException(IamErrorCode.UNAUTHORIZED, "id_token audience mismatch");
            }
            return claims;
        } catch (ParseException ex) {
            throw new IamException(IamErrorCode.UNAUTHORIZED, "id_token is invalid");
        }
    }

    private void bindOrCreateSession(
            HttpServletRequest request, HttpServletResponse response, String subject, String clientId) {
        String sid = cookieService.readSid(request);
        if (sid != null) {
            IamSession existing = sessionService.find(sid).orElse(null);
            if (existing != null && subject.equals(existing.subjectId())) {
                sessionService.touch(sid);
                return;
            }
            if (existing != null && !subject.equals(existing.subjectId())) {
                throw new IamException(IamErrorCode.UNAUTHORIZED, "SSO session subject does not match id_token");
            }
        }
        IamSession created = sessionService.create(subject, clientId, "oidc");
        cookieService.write(response, created, sessionService.ttl());
    }

    private void discardTokens(TokenResponse tokens) {
        if (tokens == null) {
            return;
        }
        tokenRevocationService.revoke(tokens.refreshToken(), "refresh_token");
        tokenRevocationService.revoke(tokens.accessToken(), "access_token");
        log.debug("Admin BFF discarded OAuth tokens; browser keeps only the SSO session cookie");
    }

    static String randomVerifier() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
