package com.authservice.authservice.controller;

import com.authservice.authservice.dto.AuthResponseDTO;
import com.authservice.authservice.dto.CredentialsDTO;
import com.authservice.authservice.service.AuthenticationService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthenticationController {
    private final AuthenticationService authenticationService;

    @Autowired
    public AuthenticationController(AuthenticationService authenticationService){
        this.authenticationService = authenticationService;
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponseDTO> login(@Valid @RequestBody CredentialsDTO credentialsDTO){
        String jwtToken = authenticationService.login(credentialsDTO);
        AuthResponseDTO responseDTO = new AuthResponseDTO(jwtToken);
        return ResponseEntity.ok(responseDTO);
    }
}
