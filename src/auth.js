const crypto = require('crypto');

// Vulnerability 16: Weak password hashing
function hashPassword(password) {
  // Using weak MD5 hash for passwords
  return crypto.createHash('md5').update(password).digest('hex');
}

// Vulnerability 17: Insecure JWT implementation
function generateJWT(user) {
  // No signature verification, easily forgeable
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64');
  const payload = Buffer.from(JSON.stringify(user)).toString('base64');
  return `${header}.${payload}.`;
}

// Vulnerability 18: Insecure session management
const sessions = {};

function createSession(userId) {
  const sessionId = Math.random().toString(36).substring(2, 15);
  sessions[sessionId] = {
    userId,
    createdAt: new Date(),
    // No expiration time set
  };
  return sessionId;
}

// Vulnerability 19: No rate limiting
function authenticateUser(username, password) {
  // No rate limiting, vulnerable to brute force attacks
  const hashedPassword = hashPassword(password);
  // Simulated user lookup
  if (username === 'admin' && hashedPassword === hashPassword('admin123')) {
    return { id: 1, username: 'admin', role: 'admin' };
  }
  return null;
}

module.exports = {
  hashPassword,
  generateJWT,
  createSession,
  authenticateUser
};
