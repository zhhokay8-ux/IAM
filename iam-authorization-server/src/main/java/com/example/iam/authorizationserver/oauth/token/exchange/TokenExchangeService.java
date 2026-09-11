package com.example.iam.authorizationserver.oauth.token.exchange;

import com.example.iam.authorizationserver.oauth.token.TokenResponse;
import com.example.iam.clientregistry.entity.IamClientEntity;

public interface TokenExchangeService {

    TokenResponse exchange(TokenExchangeRequest request, IamClientEntity client);
}
