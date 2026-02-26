package com.vunetsystems.sms.client;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

import static jakarta.ws.rs.core.HttpHeaders.CONTENT_TYPE;

public class HttpClientInternal {
    public static HttpResponse<String> sendOtpPost(Map<String,String> headers, String body, String apiUrl) throws Exception{

        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();

        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(new URI(apiUrl))
                .POST(HttpRequest.BodyPublishers.ofString(body));

        for(Map.Entry<String,String> pair : headers.entrySet()){
            requestBuilder.header(pair.getKey(), pair.getValue());
        }

        HttpRequest request = requestBuilder.build();

        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }
}
