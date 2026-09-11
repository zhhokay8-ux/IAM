package com.example.iam.embed;

public interface EmbedCodeService {

    CreateEmbedCodeResponse issue(
            CreateEmbedCodeRequest request, String parentClientId, String subjectId, String sessionId);

    EmbedContext exchange(ExchangeEmbedCodeRequest request, String childClientId);
}
