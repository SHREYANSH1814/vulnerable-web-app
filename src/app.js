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
// Sanitize and validate file path
const basename = path.basename(userInput);
const filePath = path.join(__dirname, 'uploads', basename);
// Ensure resolved path is within allowed directory
const resolvedPath = path.resolve(filePath);
const allowedDir = path.resolve(__dirname, 'uploads');
if (!resolvedPath.startsWith(allowedDir)) {
  return res.status(403).json({ error: 'Access denied' });
}
fs.readFile(resolvedPath, callback);
const filePath = path.join(__dirname, 'uploads', basename);
// Ensure resolved path is within allowed directory
const resolvedPath = path.resolve(filePath);
const allowedDir = path.resolve(__dirname, 'uploads');
if (!resolvedPath.startsWith(allowedDir)) {
  return res.status(403).json({ error: 'Access denied' });
}
fs.readFile(resolvedPath, callback);
    }
    res.send(data);
  });
});

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
// Sanitize and validate file path
const basename = path.basename(userInput);
const filePath = path.join(__dirname, 'uploads', basename);
// Ensure resolved path is within allowed directory
const resolvedPath = path.resolve(filePath);
const allowedDir = path.resolve(__dirname, 'uploads');
if (!resolvedPath.startsWith(allowedDir)) {
  return res.status(403).json({ error: 'Access denied' });
}
fs.readFile(resolvedPath, callback);

// Vulnerability 8: Path traversal
app.get('/download', (req, res) => {
  const file = req.query.file;
  // Path traversal vulnerability
  const filePath = path.join(__dirname, file);
  res.sendFile(filePath);
});

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
const args = minimist(process.argv.slice(2));
const debug = args.debug || false;

if (debug) {
  // Exposing sensitive information in debug mode
  console.log('Database credentials:', { dbUser, dbPassword });
}

app.listen(port, () => {
  console.log(`Vulnerable app listening at http://localhost:${port}`);
});
