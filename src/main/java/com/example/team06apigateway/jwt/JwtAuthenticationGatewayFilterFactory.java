package com.example.team06apigateway.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.security.Key;

@Component
@Slf4j
public class JwtAuthenticationGatewayFilterFactory extends AbstractGatewayFilterFactory<JwtAuthenticationGatewayFilterFactory.Config> {

    private final JwtConfigProperties jwtConfigProperties;

    public JwtAuthenticationGatewayFilterFactory(JwtConfigProperties jwtConfigProperties) {
        super(Config.class);
        this.jwtConfigProperties = jwtConfigProperties;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String path = request.getURI().getPath();

            AntPathMatcher matcher = new AntPathMatcher();
            boolean requiresAuth = jwtConfigProperties.getAllProtectedPaths().stream()
                    .anyMatch(pattern -> matcher.match(pattern, path));

            if (!requiresAuth) {
                log.info("paths: {}",jwtConfigProperties.getAllProtectedPaths().toString());
                log.info("JWT 인증 패스: {}", path);
                return chain.filter(exchange);
            }

            String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                log.warn("Missing or InvalidAuthorization header: {}", authHeader);
                return onError(exchange, "Missing or invalid Authorization header", HttpStatus.UNAUTHORIZED);
            }

            String token = authHeader.substring(7);
            try {
                Claims claims = Jwts.parserBuilder()
                        .setSigningKey(getSigningKey())
                        .build()
                        .parseClaimsJws(token)
                        .getBody();

                String username = claims.getSubject();
                String role = claims.get("role", String.class);
                Long userId = claims.get("userId", Long.class);

                if (jwtConfigProperties.getProtectedPaths().getAdminPaths().stream()
                        .anyMatch(pattern -> matcher.match(pattern, path)) && !role.equals("ROLE_ADMIN")) {
                    return onError(exchange, "Access denied: ADMIN only", HttpStatus.FORBIDDEN);
                }

                log.info("JWT Parsing 성공");
                log.info("username={}, role={}, userId={}", username, role, userId);

                ServerHttpRequest mutatedRequest = request.mutate()
                        .header("username", username)
                        .header("role", role)
                        .header("userId", String.valueOf(userId))
                        .build();

                return chain.filter(exchange.mutate().request(mutatedRequest).build());

            } catch (JwtException e) {
                return onError(exchange, "JWT validation failed: " + e.getMessage(), HttpStatus.UNAUTHORIZED);
            }
        };
    }

    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64URL.decode(jwtConfigProperties.getSecret());
        return Keys.hmacShaKeyFor(keyBytes);
    }

    private Mono<Void> onError(ServerWebExchange exchange, String message, HttpStatus status) {
        exchange.getResponse().setStatusCode(status);
        return exchange.getResponse().setComplete();
    }

    public static class Config {
        // 확장용 설정 필요 시 사용
    }
}
