package com.fiap.aula2jwtoauth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
class PrivateControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Mock
    private JwtDecoder jwtDecoder;

    @Autowired
    private JwtService jwtService;

    private String validToken;

    @BeforeEach
    void setup() {
        // Simula um usuário autenticado para gerar um token válido
        var authentication = new UsernamePasswordAuthenticationToken(
                "user", "password", List.of(new SimpleGrantedAuthority("read"))
        );
        validToken = jwtService.generateToken(authentication);
    }

    @Test
    void testAccessPrivateEndpoint_WithValidJWT() throws Exception {
        mockMvc.perform(get("/private")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + validToken)
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content().string("Hello from private API Controller"));
    }

    @Test
    void testAccessPrivateEndpoint_WithoutJWT() throws Exception {
        mockMvc.perform(get("/private")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void testAccessPrivateEndpoint_WithInvalidJWT() throws Exception {
        mockMvc.perform(get("/private")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer invalid_token")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void testJwtService_GenerateAndValidateToken() {
        var authentication = new UsernamePasswordAuthenticationToken(
                "user", "password", List.of(new SimpleGrantedAuthority("read"))
        );
        String token = jwtService.generateToken(authentication);

        // Verifica que o token é gerado corretamente e pode ser validado
        assertThat(token).isNotBlank();
        assertThat(jwtService.validateToken(token)).isTrue();
    }

    @Test
    void testJwtService_ValidateExpiredToken() {
        var authentication = new UsernamePasswordAuthenticationToken(
                "user", "password", List.of(new SimpleGrantedAuthority("read"))
        );

        // Gera um token com expiração no passado
        String expiredToken = jwtService.generateToken(authentication).replace(
                jwtService.generateToken(authentication).substring(0, 10), "eyJhbGciOiJIUzI1NiJ9"
        );

        assertThat(jwtService.validateToken(expiredToken)).isFalse();
    }

}