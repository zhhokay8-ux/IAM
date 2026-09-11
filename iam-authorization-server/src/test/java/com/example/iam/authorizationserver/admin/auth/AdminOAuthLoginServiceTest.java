package com.example.iam.authorizationserver.admin.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.iam.admin.config.IamAdminProperties;
import com.example.iam.audit.AuditEvent;
import com.example.iam.audit.IamAuditService;
import com.example.iam.authorizationserver.oauth.revoke.TokenRevocationService;
import com.example.iam.authorizationserver.oauth.token.TokenAuthenticationService;
import com.example.iam.authorizationserver.oauth.token.TokenService;
import com.example.iam.authorizationserver.sso.SsoCookieService;
import com.example.iam.clientregistry.validation.IamRedirectUriValidator;
import com.example.iam.common.error.IamErrorCode;
import com.example.iam.common.error.IamException;
import com.example.iam.session.IamSessionService;
import com.example.iam.token.oauth.PkceService;
import com.example.iam.token.signing.JwtSigner;
import java.net.URI;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

@ExtendWith(MockitoExtension.class)
class AdminOAuthLoginServiceTest {

    @Mock
    private IamRedirectUriValidator redirectUriValidator;

    @Mock
    private PkceService pkceService;

    @Mock
    private AdminOAuthPendingRepository pendingRepository;

    @Mock
    private TokenAuthenticationService tokenAuthenticationService;

    @Mock
    private TokenService tokenService;

    @Mock
    private TokenRevocationService tokenRevocationService;

    @Mock
    private JwtSigner jwtSigner;

    @Mock
    private IamSessionService sessionService;

    @Mock
    private SsoCookieService cookieService;

    @Mock
    private IamAuditService auditService;

    private IamAdminProperties properties;
    private AdminOAuthLoginService service;

    @BeforeEach
    void setUp() {
        properties = new IamAdminProperties();
        properties.getOauth().setClientId("iam-admin");
        properties.getOauth().setRedirectUri("http://localhost:8080/admin/callback");
        properties.getOauth().setPostLoginUri("http://localhost:8080/admin");
        properties.getOauth().setClientSecret("secret");
        service = new AdminOAuthLoginService(
                properties,
                redirectUriValidator,
                pkceService,
                pendingRepository,
                tokenAuthenticationService,
                tokenService,
                tokenRevocationService,
                jwtSigner,
                sessionService,
                cookieService,
                auditService);
    }

    @Test
    void startLoginUsesAuthorizationCodePkceStateNonceAndExactRedirect() {
        when(pkceService.challengeS256(any())).thenReturn("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        URI location = service.startLogin();
        assertThat(location.getPath()).isEqualTo("/oauth2/authorize");
        assertThat(location.getQuery()).contains("response_type=code");
        assertThat(location.getQuery()).contains("code_challenge_method=S256");
        assertThat(location.getQuery()).contains("code_challenge=");
        assertThat(location.getQuery()).contains("state=");
        assertThat(location.getQuery()).contains("nonce=");
        assertThat(location.getQuery()).contains("redirect_uri=http://localhost:8080/admin/callback");
        assertThat(location.getQuery()).doesNotContain("*");
        ArgumentCaptor<AdminOAuthPending> captor = ArgumentCaptor.forClass(AdminOAuthPending.class);
        verify(pendingRepository).save(captor.capture());
        assertThat(captor.getValue().codeVerifier()).hasSizeGreaterThanOrEqualTo(43);
        verify(redirectUriValidator).validateSyntax("http://localhost:8080/admin/callback");
    }

    @Test
    void callbackErrorIsUnauthorized() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        assertThatThrownBy(() -> service.completeCallback(null, "st", "access_denied", request, response))
                .isInstanceOf(IamException.class)
                .extracting(ex -> ((IamException) ex).getErrorCode())
                .isEqualTo(IamErrorCode.UNAUTHORIZED);
        verify(auditService).failure(AuditEvent.LOGIN_FAILURE, null, "iam-admin", "access_denied");
    }

    @Test
    void unknownStateIsRejected() {
        when(pendingRepository.consumePending("missing")).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.completeCallback(
                        "code", "missing", null, new MockHttpServletRequest(), new MockHttpServletResponse()))
                .extracting(ex -> ((IamException) ex).getErrorCode())
                .isEqualTo(IamErrorCode.UNAUTHORIZED);
    }

    @Test
    void generatedVerifierIsPkceLength() {
        String verifier = AdminOAuthLoginService.randomVerifier();
        assertThat(verifier.length()).isBetween(43, 128);
        assertThat(verifier).doesNotContain("=");
    }
}
