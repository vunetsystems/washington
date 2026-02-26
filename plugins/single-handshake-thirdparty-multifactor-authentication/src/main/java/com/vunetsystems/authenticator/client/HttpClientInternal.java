package com.vunetsystems.authenticator.client;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import static jakarta.ws.rs.core.HttpHeaders.CONTENT_TYPE;

public class HttpClientInternal {
    public static HttpResponse<String> sendPost(String body, String apiUrl, String contentType, String characterEncoding) throws Exception{

        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();


        HttpRequest request = HttpRequest.newBuilder()
                .uri(new URI(apiUrl))
                .header(CONTENT_TYPE, contentType)
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        return response;

        }
}
