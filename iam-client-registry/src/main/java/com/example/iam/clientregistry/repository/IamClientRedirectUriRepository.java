package com.example.iam.clientregistry.repository;

import com.example.iam.clientregistry.entity.IamClientRedirectUriEntity;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface IamClientRedirectUriRepository extends JpaRepository<IamClientRedirectUriEntity, UUID> {
    Optional<IamClientRedirectUriEntity> findByClientIdAndRedirectUriAndUriType(
            UUID clientId, String redirectUri, String uriType);
    List<IamClientRedirectUriEntity> findByClientId(UUID clientId);
    List<IamClientRedirectUriEntity> findByUriType(String uriType);
}
