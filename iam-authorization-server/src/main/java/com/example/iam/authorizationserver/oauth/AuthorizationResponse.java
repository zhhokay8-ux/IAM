package com.example.iam.authorizationserver.oauth;

import java.net.URI;

public record AuthorizationResponse(URI redirectLocation) {
}
