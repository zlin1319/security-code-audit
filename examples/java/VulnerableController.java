package com.example.vulnerable;

import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.URL;
import java.net.HttpURLConnection;
import java.sql.*;

/**
 * Intentionally vulnerable Java controller for security testing.
 * DO NOT USE IN PRODUCTION.
 */
@Controller
public class VulnerableController {

    // SQL Injection (CWE-89)
    @GetMapping("/user")
    @ResponseBody
    public String getUser(@RequestParam String id) {
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "pass");
            Statement stmt = conn.createStatement();
            // VULNERABLE: Direct string concatenation in SQL
            String query = "SELECT * FROM users WHERE id = " + id;
            ResultSet rs = stmt.executeQuery(query);
            return rs.next() ? rs.getString("name") : "Not found";
        } catch (SQLException e) {
            e.printStackTrace();
            return "Error";
        }
    }

    // Command Injection (CWE-78)
    @GetMapping("/ping")
    @ResponseBody
    public String ping(@RequestParam String host) {
        try {
            // VULNERABLE: User input passed to Runtime.exec()
            Process process = Runtime.getRuntime().exec("ping -c 4 " + host);
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            return output.toString();
        } catch (IOException e) {
            return "Error: " + e.getMessage();
        }
    }

    // Path Traversal (CWE-22)
    @GetMapping("/download")
    @ResponseBody
    public void download(@RequestParam String filename, HttpServletResponse response) throws IOException {
        // VULNERABLE: User-controlled path without validation
        File file = new File("/app/uploads/" + filename);
        FileInputStream fis = new FileInputStream(file);
        OutputStream out = response.getOutputStream();
        byte[] buffer = new byte[1024];
        int bytesRead;
        while ((bytesRead = fis.read(buffer)) != -1) {
            out.write(buffer, 0, bytesRead);
        }
        fis.close();
    }

    // SSRF (CWE-918)
    @GetMapping("/fetch")
    @ResponseBody
    public String fetchUrl(@RequestParam String url) {
        try {
            // VULNERABLE: User-controlled URL
            URL target = new URL(url);
            HttpURLConnection conn = (HttpURLConnection) target.openConnection();
            conn.setRequestMethod("GET");
            BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            StringBuilder content = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line);
            }
            reader.close();
            return content.toString();
        } catch (IOException e) {
            return "Error: " + e.getMessage();
        }
    }

    // XSS - Reflected (CWE-79)
    @GetMapping("/greet")
    public void greet(@RequestParam String name, HttpServletResponse response) throws IOException {
        // VULNERABLE: Direct output without encoding
        response.setContentType("text/html");
        response.getWriter().write("<h1>Hello, " + name + "!</h1>");
    }

    // Insecure Deserialization (CWE-502)
    @PostMapping("/import")
    @ResponseBody
    public String importData(@RequestBody byte[] data) {
        try {
            // VULNERABLE: Deserializing untrusted data
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
            Object obj = ois.readObject();
            return "Imported: " + obj.getClass().getName();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // Weak Hashing (CWE-328)
    @PostMapping("/hash")
    @ResponseBody
    public String hashPassword(@RequestParam String password) {
        try {
            // VULNERABLE: Using weak hash algorithm
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(password.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                hexString.append(String.format("%02x", b));
            }
            return hexString.toString();
        } catch (Exception e) {
            return "Error";
        }
    }

    // Insecure Random (CWE-330)
    @GetMapping("/token")
    @ResponseBody
    public String generateToken() {
        // VULNERABLE: Using insecure random for security token
        Random random = new Random();
        int token = random.nextInt(1000000);
        return String.valueOf(token);
    }

    // Hardcoded Credentials (CWE-798)
    private static final String API_KEY = "demo_insecure_api_key";
    private static final String DB_PASSWORD = "SuperSecret123!";

    @GetMapping("/config")
    @ResponseBody
    public String getConfig() {
        // VULNERABLE: Exposing sensitive info
        return "API Key: " + API_KEY;
    }

    // Missing Authorization (CWE-306)
    @GetMapping("/admin/users")
    @ResponseBody
    public String listAllUsers() {
        // VULNERABLE: No @Secured or @PreAuthorize
        return "All user data here";
    }
}
