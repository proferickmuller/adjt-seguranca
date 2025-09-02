package com.fiap.aula2jwtoauth;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class JwtService {

    // Armazene os tokens revogados em um Set (simula uma lista negra de tokens)
    private static final Set<String> revokedTokens = new HashSet<>();

    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;

    public JwtService(JwtEncoder jwtEncoder, JwtDecoder jwtDecoder) {
        this.jwtEncoder = jwtEncoder;
        this.jwtDecoder = jwtDecoder;
    }

    public String generateToken(Authentication authentication) {

        Instant now = Instant.now();
        long expiry = 3600L;

        String scopes = authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));

        var claims = JwtClaimsSet.builder()
                .issuer("aula2jwtoauth")
                .issuedAt(now)
                .expiresAt(now.plusSeconds(expiry))
                .subject(authentication.getName())
                .claim("scope", scopes)
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    public boolean validateToken(String token) {
        try {
            Jwt jwt = jwtDecoder.decode(token); // Decodifica e valida o token

            // Verificação de expiração
            if (jwt.getExpiresAt().isBefore(Instant.now())) {
                throw new JwtException("Token expirado");
            }

            // Verificação de emissor
            String expectedIssuer = "aula2jwtoauth";
            if (!expectedIssuer.equals(jwt.getClaim("iss"))) {
                throw new JwtException("Emissor inválido");
            }

            // Verificação de claims personalizadas
            String role = jwt.getClaim("scope");
            if (!"read".equals(role)) {
                throw new JwtException("Função de usuário inválida");
            }

            // Verificação de token revogado
            String jti = jwt.getClaim("jti");
            if (isTokenRevoked(jti)) {
                throw new JwtException("Token revogado");
            }

            return true; // Token válido

        } catch (JwtException e) {
            System.out.println("Token inválido: " + e.getMessage());
            return false;
        }
    }

    /**
     * Verifica se o token foi revogado.
     *
     * @param jti O ID do token (JWT ID)
     * @return true se o token foi revogado, false caso contrário
     */
    public boolean isTokenRevoked(String jti) {
        // Verifique se o token está na lista de tokens revogados
        return revokedTokens.contains(jti);
    }

    /**
     * Revoga um token adicionando seu ID (jti) à lista negra.
     *
     * @param jti O ID do token (JWT ID)
     */
    public boolean revokeToken(String jti) {
        if (jti == null || jti.isBlank()) {
            throw new IllegalArgumentException("Token ID (jti) não pode ser nulo ou vazio.");
        }
        return revokedTokens.add(jti); // Retorna true se foi adicionado, false se já existia
    }

}