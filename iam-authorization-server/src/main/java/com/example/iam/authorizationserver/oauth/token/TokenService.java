package com.example.iam.authorizationserver.oauth.token;

import com.example.iam.clientregistry.entity.IamClientEntity;

public interface TokenService {

    TokenResponse issue(TokenRequest request, IamClientEntity client);
}
