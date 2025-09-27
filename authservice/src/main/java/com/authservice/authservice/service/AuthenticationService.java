package com.authservice.authservice.service;

import com.authservice.authservice.dto.CredentialsDTO;
import com.authservice.authservice.exceptions.InvalidCredentialsException;
import com.authservice.authservice.jwt.JwtProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

@Service
public class AuthenticationService {

    private final WebClient.Builder webClientBuilder;
    private final JwtProvider jwtProvider;

    @Value("${userservice.api.url}")
    private String userServiceUrl;

    @Value("${api.internal.secret}")
    private String internalApiSecret;

    public AuthenticationService(WebClient.Builder webClientBuilder, JwtProvider jwtProvider){
        this.webClientBuilder = webClientBuilder;
        this.jwtProvider = jwtProvider;
    }

    private void validateCredentialsWithUserService(CredentialsDTO credentials){
        WebClient webClient = webClientBuilder.baseUrl(userServiceUrl).build();
        webClient.post()
                .uri("/internal/users/validate-credential")
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .header("X-Internal-Secret", internalApiSecret)
                .body(Mono.just(credentials), CredentialsDTO.class)
                .retrieve()
                .onStatus(
                        status -> status.is4xxClientError(),
                        response -> Mono.error(new InvalidCredentialsException("Credenciais inválidas fornecidas."))
                )
                .toBodilessEntity()
                .block();
    }

    public String login(CredentialsDTO credentials) {
        validateCredentialsWithUserService(credentials);
        return jwtProvider.generateToken(credentials.getUserName());
    }






}
