const fs = require('fs');
const { exec } = require('child_process');
const crypto = require('crypto');

// Vulnerability 11: Insecure random number generation
function generateToken() {
  // Using Math.random() for security-sensitive operations
  return Math.random().toString(36).substring(2, 15);
}

// Vulnerability 12: Unsafe regex leading to ReDoS
function validateEmail(email) {
  // Vulnerable to ReDoS (Regular Expression Denial of Service)
  const emailRegex = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
  return emailRegex.test(email);
}

// Vulnerability 13: Insecure file operations
function writeLog(logData) {
  // Synchronous file operations can lead to DoS
  fs.writeFileSync('./logs/app.log', logData, { flag: 'a' });
}

// Vulnerability 14: Hardcoded encryption key
// Generate random IV for each encryption
const iv = crypto.randomBytes(16);
const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
const encrypted = cipher.update(data, 'utf8', 'hex');
// Prepend IV to encrypted data for decryption
return iv.toString('hex') + ':' + encrypted;
  return encrypted.toString('hex');
}

// Vulnerability 15: Prototype pollution
function merge(target, source) {
  for (let key in source) {
    if (typeof source[key] === 'object') {
      if (!target[key]) target[key] = {};
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

module.exports = {
  generateToken,
  validateEmail,
  writeLog,
  encryptData,
  merge
};
