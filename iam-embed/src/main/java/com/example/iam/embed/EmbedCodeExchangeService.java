package com.example.iam.embed;

public interface EmbedCodeExchangeService {

    EmbedContext exchange(ExchangeEmbedCodeRequest request, String childClientId);
}
