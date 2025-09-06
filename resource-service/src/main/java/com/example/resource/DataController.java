package com.example.resource;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class DataController {

    @GetMapping("/api/data")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<?> data() {
        return ResponseEntity.ok(Map.of(
                "message", "Protected data from resource-service (ROLE_USER required)",
                "service", "resource-service",
                "timestamp", System.currentTimeMillis()
        ));
    }
}
