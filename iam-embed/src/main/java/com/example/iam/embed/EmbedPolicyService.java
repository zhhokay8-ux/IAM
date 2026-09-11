package com.example.iam.embed;

import com.example.iam.embed.entity.IamEmbedPolicyEntity;
import java.util.List;
import java.util.UUID;

public interface EmbedPolicyService {

    IamEmbedPolicyEntity requireActive(String parentClientId, String childClientId, String origin, String path);

    EmbedPolicyView create(String parentClientId, String childClientId, String origin, String path);

    EmbedPolicyView update(UUID id, String origin, String path);

    EmbedPolicyView get(UUID id);

    List<EmbedPolicyView> list(String parentClientId, String childClientId);

    EmbedPolicyView enable(UUID id);

    EmbedPolicyView disable(UUID id);
}
