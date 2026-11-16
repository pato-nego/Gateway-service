package store.gateway;

import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GatewayResource {

    // public: the AuthorizationFilter is a GlobalFilter and only runs on routes,
    // not on the gateway's own endpoints. Answer only what a health check needs
    // (the hostname tells which replica answered); never return System.getenv(),
    // it carries passwords, tokens and connection strings injected as variables
    @GetMapping("/health-check")
    public ResponseEntity<Map<String, String>> healthCheck() {
        return ResponseEntity.ok(Map.of(
            "hostname", System.getenv().getOrDefault("HOSTNAME", "unknown")
        ));
    }

}
