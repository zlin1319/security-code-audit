/**
 * Intentionally vulnerable Node.js/Express application for security testing.
 * DO NOT USE IN PRODUCTION.
 */

const express = require('express');
const mysql = require('mysql');
const { exec, execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Database connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'demo-insecure-password',  // VULNERABLE: Hardcoded credentials
    database: 'app_db'
});

// Vulnerable: Hardcoded secrets
const API_KEY = 'demo_insecure_api_key';
const JWT_SECRET = 'demo_insecure_jwt_secret';

/**
 * SQL Injection (CWE-89)
 */
app.get('/api/user', (req, res) => {
    const userId = req.query.id;

    // VULNERABLE: String concatenation in SQL
    const query = `SELECT * FROM users WHERE id = ${userId}`;

    db.query(query, (err, results) => {
        if (err) {
            // VULNERABLE: Detailed error exposure
            return res.status(500).json({ error: err.message, stack: err.stack });
        }
        res.json(results);
    });
});

/**
 * Another SQL Injection using string concatenation
 */
app.post('/api/search', (req, res) => {
    const { name } = req.body;

    // VULNERABLE: Concatenation with user input
    const query = "SELECT * FROM users WHERE name = '" + name + "'";

    db.query(query, (err, results) => {
        if (err) return res.status(500).send(err);
        res.json(results);
    });
});

/**
 * Command Injection (CWE-78)
 */
app.get('/api/ping', (req, res) => {
    const host = req.query.host;

    // VULNERABLE: User input in shell command
    exec(`ping -c 4 ${host}`, (error, stdout, stderr) => {
        if (error) return res.status(500).send(error.message);
        res.send(stdout);
    });
});

/**
 * Another Command Injection
 */
app.get('/api/dns', (req, res) => {
    const domain = req.query.domain;

    // VULNERABLE: execSync with user input
    const result = execSync(`nslookup ${domain}`);
    res.send(result.toString());
});

/**
 * Path Traversal (CWE-22)
 */
app.get('/api/file', (req, res) => {
    const filename = req.query.filename;

    // VULNERABLE: No path validation
    const filePath = path.join('/app/uploads/', filename);

    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) return res.status(404).send('File not found');
        res.send(data);
    });
});

/**
 * Server-Side Request Forgery (CWE-918)
 */
app.get('/api/fetch', async (req, res) => {
    const url = req.query.url;

    try {
        // VULNERABLE: User-controlled URL
        const response = await axios.get(url);
        res.send(response.data);
    } catch (error) {
        res.status(500).send(error.message);
    }
});

/**
 * Another SSRF vulnerability
 */
app.post('/api/webhook', async (req, res) => {
    const { webhookUrl, data } = req.body;

    // VULNERABLE: No URL validation
    try {
        await axios.post(webhookUrl, data);
        res.json({ success: true });
    } catch (error) {
        res.status(500).send(error.message);
    }
});

/**
 * Cross-Site Scripting (CWE-79) - Reflected
 */
app.get('/api/greet', (req, res) => {
    const name = req.query.name;

    // VULNERABLE: Direct HTML output without encoding
    res.send(`<h1>Hello, ${name}!</h1>`);
});

/**
 * XSS via innerHTML equivalent
 */
app.get('/api/render', (req, res) => {
    const content = req.query.content;

    // VULNERABLE: Sending HTML with user input
    res.send(`
        <html>
            <body>
                <div id="output">${content}</div>
                <script>
                    document.getElementById('output').innerHTML = '${content}';
                </script>
            </body>
        </html>
    `);
});

/**
 * Insecure Deserialization (CWE-502)
 */
app.post('/api/import', (req, res) => {
    const { serializedData } = req.body;

    // VULNERABLE: Using eval for deserialization
    const obj = eval('(' + serializedData + ')');

    res.json({ imported: obj });
});

/**
 * Weak Hashing (CWE-328)
 */
app.post('/api/hash', (req, res) => {
    const { password } = req.body;

    // VULNERABLE: Using MD5 for password hashing
    const hash = crypto.createHash('md5').update(password).digest('hex');

    res.json({ hash });
});

/**
 * Another Weak Hashing
 */
app.post('/api/hash/sha1', (req, res) => {
    const { password } = req.body;

    // VULNERABLE: Using SHA1 for password hashing
    const hash = crypto.createHash('sha1').update(password).digest('hex');

    res.json({ hash });
});

/**
 * Information Leakage (CWE-200)
 */
app.get('/api/config', (req, res) => {
    // VULNERABLE: Exposing sensitive configuration
    res.json({
        apiKey: API_KEY,
        jwtSecret: JWT_SECRET,
        dbPassword: 'demo-insecure-password'
    });
});

/**
 * Missing Authentication (CWE-306)
 */
app.get('/api/admin/users', (req, res) => {
    // VULNERABLE: No authentication check
    db.query('SELECT * FROM users', (err, results) => {
        if (err) return res.status(500).send(err);
        res.json(results);
    });
});

/**
 * Insecure Direct Object Reference (CWE-639)
 */
app.get('/api/order/:orderId', (req, res) => {
    const orderId = req.params.orderId;
    // VULNERABLE: No ownership verification

    const query = `SELECT * FROM orders WHERE id = ${orderId}`;

    db.query(query, (err, results) => {
        if (err) return res.status(500).send(err);
        res.json(results[0]);
    });
});

/**
 * Code Injection via setTimeout
 */
app.post('/api/delay', (req, res) => {
    const { code, delay } = req.body;

    // VULNERABLE: User input in setTimeout
    setTimeout(code, delay);

    res.json({ scheduled: true });
});

// Start server
app.listen(3000, () => {
    console.log('Vulnerable server running on port 3000');
});

module.exports = app;
