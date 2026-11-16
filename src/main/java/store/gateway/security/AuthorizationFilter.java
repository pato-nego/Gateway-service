package store.gateway.security;

import java.time.Duration;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

@Component
public class AuthorizationFilter implements GlobalFilter {

    private static final Logger logger = LoggerFactory.getLogger(AuthorizationFilter.class);

    public static final String AUTH_COOKIE_TOKEN = "__store_jwt_token";
    public static final String AUTH_SERVICE_URL = "http://auth:8080";
    public static final String AUTH_SERVICE_TOKEN_SOLVE = "/auth/solve";
    private static final Duration AUTH_TIMEOUT = Duration.ofSeconds(3);

    private final RouterValidator routerValidator;

    // built once and reused by every request: the client is thread-safe
    private final WebClient authClient;

    public AuthorizationFilter(RouterValidator routerValidator, WebClient.Builder builder) {
        this.routerValidator = routerValidator;
        this.authClient = builder
            .baseUrl(AUTH_SERVICE_URL)
            .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
            .build();
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        // get the request content
        final ServerHttpRequest request = exchange.getRequest();

        // check if the route is open
        if (!routerValidator.isSecured.test(request)) {
            logger.debug("this route is open");
            return chain.filter(exchange);
        }

        // route is not open: the cookie with the jwt is required
        final HttpCookie cookie = request.getCookies().getFirst(AUTH_COOKIE_TOKEN);
        if (cookie == null || cookie.getValue().isBlank()) {
            return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED));
        }

        logger.debug("I got the cookie");
        return requestAuthTokenSolve(exchange, chain, cookie.getValue().trim());
    }

    private Mono<Void> requestAuthTokenSolve(
        ServerWebExchange exchange,
        GatewayFilterChain chain,
        final String jwt) {

        return authClient.post()
            .uri(AUTH_SERVICE_TOKEN_SOLVE)
            .bodyValue(Map.of("token", jwt))
            .retrieve()
            // an invalid or expired token is a 401, not a 500
            .onStatus(HttpStatusCode::is4xxClientError,
                response -> Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid token")))
            .bodyToMono(new ParameterizedTypeReference<Map<String, String>>() {})
            // a hung auth service must not hold requests in the gateway forever
            .timeout(AUTH_TIMEOUT)
            .switchIfEmpty(Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid token")))
            .flatMap(map -> {
                logger.debug(map.toString());
                return chain.filter(updateRequest(exchange, map.get("idAccount")));
            });
    }

    private ServerWebExchange updateRequest(ServerWebExchange exchange, String idAccount) {
        return exchange.mutate()
            .request(
                exchange.getRequest()
                    .mutate()
                    .header("id-account", idAccount)
                    .build()
            ).build();
    }

}
