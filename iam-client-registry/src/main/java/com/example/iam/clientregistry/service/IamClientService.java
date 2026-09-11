package com.example.iam.clientregistry.service;

import com.example.iam.clientregistry.dto.ClientResponse;
import com.example.iam.clientregistry.dto.CreateClientRequest;
import com.example.iam.clientregistry.dto.RedirectUriInput;
import com.example.iam.clientregistry.dto.RotatedSecretResponse;
import com.example.iam.clientregistry.dto.UpdateClientRequest;
import com.example.iam.clientregistry.entity.IamClientEntity;
import java.util.List;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface IamClientService {

    ClientResponse create(CreateClientRequest request);

    ClientResponse update(String clientId, UpdateClientRequest request);

    ClientResponse get(String clientId);

    Page<ClientResponse> search(String query, String status, Pageable pageable);

    ClientResponse disable(String clientId);

    ClientResponse enable(String clientId);

    RotatedSecretResponse rotateSecret(String clientId);

    ClientResponse replaceRedirectUris(String clientId, List<RedirectUriInput> redirectUris);

    IamClientEntity requireActiveClient(String clientId);

    ClientResponse dynamicRegister(CreateClientRequest request);
}
