package com.fiap.aula2jwtoauth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class JwtServiceTest {

    @Mock
    private JwtEncoder jwtEncoder;

    @Mock
    private JwtDecoder jwtDecoder;

    @InjectMocks
    private JwtService jwtService; // Aqui usamos o serviço real com mocks injetados

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        //O spy(jwtService) permite que validateToken execute normalmente,
        //mas ainda conseguimos mockar isTokenRevoked.
        jwtService = spy(jwtService); // Transforma a instância real em um Spy
    }

    @Test
    void testGenerateToken() {
        // Arrange
        Authentication authentication = mock(Authentication.class);
        GrantedAuthority authority = mock(GrantedAuthority.class);
        when(authentication.getName()).thenReturn("user");
        when(authority.getAuthority()).thenReturn("read");

        Jwt jwt = mock(Jwt.class);
        when(jwtEncoder.encode(any(JwtEncoderParameters.class))).thenReturn(jwt);
        when(jwt.getTokenValue()).thenReturn("mockedToken");

        // Act
        String token = jwtService.generateToken(authentication);

        // Assert
        assertNotNull(token);
        assertEquals("mockedToken", token);
        verify(jwtEncoder, times(1)).encode(any(JwtEncoderParameters.class));
    }

    @Test
    void testValidateToken_ValidToken() {
        // Arrange
        String token = "validToken";
        Jwt jwt = Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .claim("scope", "read")
                .claim("sub", "username")
                .claim("exp", Instant.now().plusSeconds(3600))
                .claim("iss", "aula2jwtoauth")
                .build();
        when(jwtDecoder.decode(token)).thenReturn(jwt);

        // Act
        boolean isValid = jwtService.validateToken(token);

        // Assert
        assertTrue(isValid);
        verify(jwtDecoder, times(1)).decode(token);
    }


    @Test
    void testValidateToken_ExpiredToken() {
        // Arrange
        String token = "expiredToken";
        Jwt jwt = mock(Jwt.class);
        when(jwtDecoder.decode(token)).thenReturn(jwt);
        when(jwt.getExpiresAt()).thenReturn(Instant.now().minusSeconds(3600));

        // Act
        boolean isValid = jwtService.validateToken(token);

        // Assert
        assertFalse(isValid);
        verify(jwtDecoder, times(1)).decode(token);
    }

    @Test
    void testValidateToken_InvalidIssuer() {
        // Arrange
        String token = "invalidIssuerToken";
        Jwt jwt = Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .claim("scope", "read")
                .claim("sub", "username")
                .claim("exp", Instant.now().plusSeconds(3600))
                .claim("iss", "invalidIssuer")
                .build();
        when(jwtDecoder.decode(token)).thenReturn(jwt);

        // Act
        boolean isValid = jwtService.validateToken(token);

        // Assert
        assertFalse(isValid);
        verify(jwtDecoder, times(1)).decode(token);
    }

    @Test
    void testValidateToken_InvalidRole() {
        // Arrange
        String token = "invalidRoleToken";
        Jwt jwt = Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .claim("scope", "write")
                .claim("sub", "username")
                .claim("exp", Instant.now().plusSeconds(3600))
                .claim("iss", "aula2jwtoauth")
                .build();

        // Simula a decodificação do token
        when(jwtDecoder.decode(token)).thenReturn(jwt);

        // Act
        boolean isValid = jwtService.validateToken(token);

        // Assert
        assertFalse(isValid);
        verify(jwtDecoder, times(1)).decode(token);
    }

    @Test
    void testValidateToken_RevokedToken() {
        // Arrange
        String token = "revokedToken";
        Jwt jwt = Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .claim("scope", "read")
                .claim("sub", "username")
                .claim("exp", Instant.now().plusSeconds(3600))
                .claim("iss", "aula2jwtoauth")
                .claim("jti", "revokedJti")
                .build();

        // Simula a decodificação do token
        when(jwtDecoder.decode(token)).thenReturn(jwt);

        // Simula que o token foi revogado
        doReturn(true).when(jwtService).isTokenRevoked("revokedJti");

        // Act
        boolean isValid = jwtService.validateToken(token); // Agora chamamos a lógica real!

        // Assert
        assertFalse(isValid, "O token deve ser inválido por estar revogado.");
        // Verifica que o decoder foi chamado
        verify(jwtDecoder, times(1)).decode(token);
        // Verifica que a revogação foi verificada
        verify(jwtService, times(1)).isTokenRevoked("revokedJti");
    }

    @Test
    void testRevokeToken_TokenAlreadyRevoked() {
        // Arrange
        String token = "exampleJti";
        jwtService.revokeToken(token);

        // Act
        boolean result = jwtService.revokeToken(token);

        // Assert
        assertFalse(result, "Revogar o mesmo token novamente deve retornar false.");
    }

    @Test
    void testRevokeToken_NullOrEmptyToken() {
        // Arrange
        String nullToken = null;
        String emptyToken = "";

        // Act
        Executable revokeNullToken = () -> jwtService.revokeToken(nullToken);
        Executable revokeEmptyToken = () -> jwtService.revokeToken(emptyToken);

        // Assert
        assertThrows(IllegalArgumentException.class, revokeNullToken, "Deve lançar exceção para token nulo.");
        assertThrows(IllegalArgumentException.class, revokeEmptyToken, "Deve lançar exceção para token vazio.");
    }

}