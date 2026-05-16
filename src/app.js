const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const fs = require('fs');
const serialize = require('node-serialize');
const { exec } = require('child_process');
const crypto = require('crypto');
const mongoose = require('mongoose');
const minimist = require('minimist');

const app = express();
const port = 3000;

// Vulnerability 1: Insecure parsing of user input
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Vulnerability 2: Hardcoded credentials
const dbUser = 'admin';
const dbPassword = 'super_secret_password123';
const dbConnection = `mongodb://localhost:27017/vulnerable_db`;
null
  fs.readFile(`./data/users/${userId}.json`, 'utf8', (err, data) => {
    if (err) {
null

// Vulnerability 4: Command injection
app.get('/ping', (req, res) => {
  const host = req.query.host;
  // Command injection vulnerability
  exec(`ping -c 4 ${host}`, (error, stdout, stderr) => {
    res.send(stdout);
  });
});

// Vulnerability 5: Insecure deserialization
app.post('/deserialize', (req, res) => {
  const userInput = req.body.data;
  // Insecure deserialization vulnerability
  const deserializedData = serialize.unserialize(userInput);
  res.send('Data processed');
});

// Vulnerability 6: Weak cryptography
app.post('/encrypt', (req, res) => {
  const { text } = req.body;
  // Using weak MD5 hash
  const hash = crypto.createHash('md5').update(text).digest('hex');
  res.send({ hash });
});

// Vulnerability 7: SQL Injection (simulated)
app.get('/search', (req, res) => {
  const query = req.query.q;
  // Simulating SQL injection vulnerability
  const sqlQuery = `SELECT * FROM products WHERE name LIKE '%${query}%'`;
  res.send(`Query executed: ${sqlQuery}`);
});
null
null

// Vulnerability 9: Cross-site scripting (XSS)
app.get('/profile', (req, res) => {
  const username = req.query.username;
  // XSS vulnerability
  res.send(`
    <html>
      <body>
        <h1>Welcome, ${username}!</h1>
      </body>
    </html>
  `);
});

// Vulnerability 10: Insecure parsing of command line arguments
null
if (debug) {
  // Exposing sensitive information in debug mode
  console.log('Database credentials:', { dbUser, dbPassword });
}

app.listen(port, () => {
  console.log(`Vulnerable app listening at http://localhost:${port}`);
});
