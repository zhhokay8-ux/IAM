package com.example.iam.token.signing;

import com.example.iam.token.entity.IamSigningKeyEntity;
import java.util.List;

public interface SigningKeyService {

    KeyMetadata createActiveKey();

    KeyMetadata getActiveKey();

    KeyMetadata getByKid(String kid);

    List<KeyMetadata> listAll();

    KeyMetadata toMetadata(IamSigningKeyEntity entity);
}
