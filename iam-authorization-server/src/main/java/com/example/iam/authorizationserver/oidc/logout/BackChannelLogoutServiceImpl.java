package com.example.iam.authorizationserver.oidc.logout;

import com.example.iam.clientregistry.domain.RedirectUriType;
import com.example.iam.clientregistry.entity.IamClientEntity;
import com.example.iam.clientregistry.entity.IamClientRedirectUriEntity;
import com.example.iam.clientregistry.repository.IamClientRedirectUriRepository;
import com.example.iam.clientregistry.repository.IamClientRepository;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.common.util.IdGenerator;
import com.example.iam.session.IamSessionService;
import com.example.iam.token.oauth.JtiRevocationService;
import com.example.iam.token.oauth.RefreshTokenFamilyService;
import com.example.iam.token.signing.JwtSigner;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class BackChannelLogoutServiceImpl implements BackChannelLogoutService {

    static final String EVENT_TYPE = "http://schemas.openid.net/event/backchannel-logout";
    static final JOSEObjectType LOGOUT_JWT = new JOSEObjectType("logout+jwt");

    private static final Logger log = LoggerFactory.getLogger(BackChannelLogoutServiceImpl.class);

    private final JwtSigner jwtSigner;
    private final String issuer;
    private final IamClientRedirectUriRepository redirectUriRepository;
    private final IamClientRepository clientRepository;
    private final BackChannelLogoutClient backChannelLogoutClient;
    private final JtiRevocationService jtiRevocationService;
    private final IamSessionService sessionService;
    private final RefreshTokenFamilyService refreshTokenFamilyService;
    private final Clock clock;

    @Autowired
    public BackChannelLogoutServiceImpl(
            JwtSigner jwtSigner,
            @Value("${iam.issuer}") String issuer,
            IamClientRedirectUriRepository redirectUriRepository,
            IamClientRepository clientRepository,
            BackChannelLogoutClient backChannelLogoutClient,
            JtiRevocationService jtiRevocationService,
            IamSessionService sessionService,
            RefreshTokenFamilyService refreshTokenFamilyService) {
        this(
                jwtSigner,
                issuer,
                redirectUriRepository,
                clientRepository,
                backChannelLogoutClient,
                jtiRevocationService,
                sessionService,
                refreshTokenFamilyService,
                Clock.systemUTC());
    }

    BackChannelLogoutServiceImpl(
            JwtSigner jwtSigner,
            String issuer,
            IamClientRedirectUriRepository redirectUriRepository,
            IamClientRepository clientRepository,
            BackChannelLogoutClient backChannelLogoutClient,
            JtiRevocationService jtiRevocationService,
            IamSessionService sessionService,
            RefreshTokenFamilyService refreshTokenFamilyService,
            Clock clock) {
        this.jwtSigner = jwtSigner;
        this.issuer = issuer;
        this.redirectUriRepository = redirectUriRepository;
        this.clientRepository = clientRepository;
        this.backChannelLogoutClient = backChannelLogoutClient;
        this.jtiRevocationService = jtiRevocationService;
        this.sessionService = sessionService;
        this.refreshTokenFamilyService = refreshTokenFamilyService;
        this.clock = clock;
    }

    @Override
    public void notifyClients(String subjectId, String sessionId) {
        List<IamClientRedirectUriEntity> callbacks =
                redirectUriRepository.findByUriType(RedirectUriType.LOGOUT_CALLBACK);
        for (IamClientRedirectUriEntity callback : callbacks) {
            IamClientEntity client = clientRepository.findById(callback.getClientId()).orElse(null);
            if (client == null) {
                continue;
            }
            try {
                String token = issueLogoutToken(client.getClientId(), subjectId, sessionId);
                backChannelLogoutClient.postLogoutToken(callback.getRedirectUri(), token);
            } catch (RuntimeException ex) {
                log.warn("back-channel logout notify failed client={}", client.getClientId(), ex);
            }
        }
    }

    @Override
    public String issueLogoutToken(String audienceClientId, String subjectId, String sessionId) {
        Instant now = clock.instant();
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .audience(audienceClientId)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(Duration.ofMinutes(2))))
                .jwtID(IdGenerator.next())
                .claim("events", Map.of(EVENT_TYPE, Map.of()));
        if (subjectId != null && !subjectId.isBlank()) {
            builder.subject(subjectId);
        }
        if (sessionId != null && !sessionId.isBlank()) {
            builder.claim("sid", sessionId);
        }
        return jwtSigner.sign(builder.build(), LOGOUT_JWT).serialize();
    }

    @Override
    public JWTClaimsSet consumeLogoutToken(String logoutToken) {
        JWTClaimsSet claims = verifyLogoutToken(logoutToken);
        String jti = claims.getJWTID();
        if (jti != null && jtiRevocationService.isRevoked(jti)) {
            throw new IamException(IamErrorCode.INVALID_LOGOUT_TOKEN, "logout token replayed");
        }
        if (jti != null) {
            jtiRevocationService.revoke(jti, Duration.ofMinutes(2));
        }
        String sid = stringClaim(claims, "sid");
        if (sid != null && !sid.isBlank()) {
            sessionService.delete(sid);
        }
        if (claims.getSubject() != null && !claims.getSubject().isBlank()) {
            try {
                refreshTokenFamilyService.revokeAllForSubject(UUID.fromString(claims.getSubject()));
            } catch (IllegalArgumentException ignored) {
                // ignore non-UUID subjects
            }
        }
        return claims;
    }

    JWTClaimsSet verifyLogoutToken(String logoutToken) {
        if (logoutToken == null || logoutToken.isBlank()) {
            throw new IamException(IamErrorCode.INVALID_LOGOUT_TOKEN, "logout_token is required");
        }
        SignedJWT jwt;
        try {
            jwt = jwtSigner.verify(logoutToken);
        } catch (IamException ex) {
            throw new IamException(IamErrorCode.INVALID_LOGOUT_TOKEN, "logout token is invalid", ex);
        }
        JWTClaimsSet claims;
        try {
            claims = jwt.getJWTClaimsSet();
        } catch (ParseException ex) {
            throw new IamException(IamErrorCode.INVALID_LOGOUT_TOKEN, "logout token claims are malformed", ex);
        }
        if (issuer == null || !issuer.equals(claims.getIssuer())) {
            throw new IamException(IamErrorCode.INVALID_LOGOUT_TOKEN, "logout token issuer is invalid");
        }
        Instant now = clock.instant();
        Date exp = claims.getExpirationTime();
        if (exp != null && now.isAfter(exp.toInstant())) {
            throw new IamException(IamErrorCode.INVALID_LOGOUT_TOKEN, "logout token expired");
        }
        Object events = claims.getClaim("events");
        if (!(events instanceof Map<?, ?> map) || !map.containsKey(EVENT_TYPE)) {
            throw new IamException(IamErrorCode.INVALID_LOGOUT_TOKEN, "logout token events claim is missing");
        }
        boolean hasSub = claims.getSubject() != null && !claims.getSubject().isBlank();
        boolean hasSid = stringClaim(claims, "sid") != null;
        if (!hasSub && !hasSid) {
            throw new IamException(IamErrorCode.INVALID_LOGOUT_TOKEN, "logout token must contain sub or sid");
        }
        return claims;
    }

    private static String stringClaim(JWTClaimsSet claims, String name) {
        Object value = claims.getClaim(name);
        if (value == null) {
            return null;
        }
        String text = value.toString();
        return text.isBlank() ? null : text;
    }
}
