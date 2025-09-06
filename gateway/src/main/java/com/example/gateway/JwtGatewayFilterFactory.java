package com.example.gateway;

import com.example.common.JwtUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.Map;

@Component("Jwt")
public class JwtGatewayFilterFactory extends AbstractGatewayFilterFactory<Object> {

    private final WebClient webClient;
    private final String authBase;

    public JwtGatewayFilterFactory(@Value("${demo.auth-base}") String authBase) {
        this.webClient = WebClient.builder().build();
        this.authBase = authBase;
    }

    @Override
    public GatewayFilter apply(Object config) {
        return (exchange, chain) -> {
            String auth = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            if (auth == null || !auth.startsWith("Bearer ")) {
                return reject(exchange, HttpStatus.UNAUTHORIZED, "Missing access token");
            }
            String token = auth.substring("Bearer ".length()).trim();

            try {
                Jws<Claims> claims = JwtUtil.parseAccess(token);
                return chain.filter(exchange);
            } catch (ExpiredJwtException eje) {
                String useServerRefresh = exchange.getRequest().getHeaders().getFirst("X-Use-Server-Refresh");
                String refreshHeader = exchange.getRequest().getHeaders().getFirst("Authorization-Refresh");
                if ("true".equalsIgnoreCase(useServerRefresh) && refreshHeader != null && refreshHeader.startsWith("Bearer ")) {
                    String refreshToken = refreshHeader.substring("Bearer ".length()).trim();
                    return serverSideRefresh(exchange, chain, refreshToken);
                }
                return custom(exchange, HttpStatus.valueOf(511), Map.of("code", 511, "message", "Access token expired; refresh required"));
            } catch (Exception e) {
                return reject(exchange, HttpStatus.UNAUTHORIZED, "Invalid access token");
            }
        };
    }

    private Mono<Void> serverSideRefresh(ServerWebExchange exchange, org.springframework.cloud.gateway.filter.GatewayFilterChain chain, String refreshToken) {
        return webClient.get()
                .uri(URI.create(authBase + "/auth/refresh"))
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + refreshToken)
                .retrieve()
                .onStatus(status -> status.value() == 401, resp -> Mono.error(new RuntimeException("Refresh token invalid or expired")))
                .bodyToMono(Map.class)
                .flatMap(body -> {
                    Object tk = body.get("token");
                    if (tk == null) {
                        return reject(exchange, HttpStatus.UNAUTHORIZED, "Refresh failed");
                    }
                    return chain.filter(exchange.mutate()
                            .request(builder -> builder.header(HttpHeaders.AUTHORIZATION, "Bearer " + tk.toString()))
                            .build())
                            .then(Mono.defer(() -> {
                                exchange.getResponse().getHeaders().add("X-New-Token", tk.toString());
                                return Mono.empty();
                            }));
                })
                .onErrorResume(e -> custom(exchange, HttpStatus.valueOf(511), Map.of("code", 511, "message", "Access token expired; refresh required")));
    }

    private Mono<Void> reject(ServerWebExchange exchange, HttpStatus status, String message) {
        return custom(exchange, status, Map.of("code", status.value(), "message", message));
    }

    private Mono<Void> custom(ServerWebExchange exchange, HttpStatus status, Map<String, Object> body) {
        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders().add(HttpHeaders.CONTENT_TYPE, "application/json;charset=UTF-8");
        byte[] bytes = ("{\"code\":" + body.get("code") + ",\"message\":\"" + body.get("message") + "\"}").getBytes();
        return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(bytes)));
    }
}
