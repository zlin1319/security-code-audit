package com.example.mixed;

import org.springframework.web.bind.annotation.*;
import java.sql.*;

/**
 * Mixed security examples - some vulnerable, some safe.
 * For demonstrating AI false positive filtering.
 */
@RestController
public class MixedSecurityController {

    /**
     * VULNERABLE: Direct string concatenation
     */
    @GetMapping("/api/vulnerable-search")
    public String vulnerableSearch(@RequestParam String keyword) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "pass");
        Statement stmt = conn.createStatement();
        // VULNERABLE: No sanitization
        String query = "SELECT * FROM products WHERE name LIKE '%" + keyword + "%'";
        ResultSet rs = stmt.executeQuery(query);
        return rs.next() ? rs.getString("name") : "Not found";
    }

    /**
     * SAFE: Uses PreparedStatement with parameterized query
     */
    @GetMapping("/api/safe-search")
    public String safeSearch(@RequestParam String keyword) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "pass");
        // SAFE: Parameterized query - no concatenation
        PreparedStatement stmt = conn.prepareStatement("SELECT * FROM products WHERE name LIKE ?");
        stmt.setString(1, "%" + keyword + "%");
        ResultSet rs = stmt.executeQuery();
        return rs.next() ? rs.getString("name") : "Not found";
    }

    /**
     * SAFE: Uses input validation before SQL
     */
    @GetMapping("/api/validated-search")
    public String validatedSearch(@RequestParam String id) throws SQLException {
        // Input validation - only allow numeric IDs
        if (!id.matches("\\d+")) {
            throw new IllegalArgumentException("Invalid ID format");
        }

        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "pass");
        Statement stmt = conn.createStatement();
        // SAFE: Input is validated to be numeric only
        String query = "SELECT * FROM users WHERE id = " + id;
        ResultSet rs = stmt.executeQuery(query);
        return rs.next() ? rs.getString("name") : "Not found";
    }

    /**
     * VULNERABLE: Command injection
     */
    @GetMapping("/api/vulnerable-ping")
    public String vulnerablePing(@RequestParam String host) throws Exception {
        // VULNERABLE: Direct command concatenation
        Process process = Runtime.getRuntime().exec("ping -c 4 " + host);
        // ... read output
        return "OK";
    }

    /**
     * SAFE: Command with allowlist validation
     */
    @GetMapping("/api/safe-ping")
    public String safePing(@RequestParam String host) throws Exception {
        // Input validation - strict allowlist
        if (!host.matches("[a-zA-Z0-9\\.\\-]+") || host.contains("..") || host.contains(";")) {
            throw new IllegalArgumentException("Invalid hostname");
        }

        // SAFE: Input is validated, using array to avoid shell interpretation
        ProcessBuilder pb = new ProcessBuilder("ping", "-c", "4", host);
        Process process = pb.start();
        return "OK";
    }
}
