package com.example.iam.token.repository;

import com.example.iam.token.entity.IamSigningKeyEntity;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface IamSigningKeyRepository extends JpaRepository<IamSigningKeyEntity, UUID> {
    Optional<IamSigningKeyEntity> findByKid(String kid);
    List<IamSigningKeyEntity> findByStatus(String status);
    List<IamSigningKeyEntity> findByStatusIn(Collection<String> statuses);
    Optional<IamSigningKeyEntity> findFirstByStatusOrderByActivatedAtDesc(String status);
}
