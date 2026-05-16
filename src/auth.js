const crypto = require('crypto');

null
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
null
  if (username === 'admin' && hashedPassword === hashPassword('admin123')) {
    return { id: 1, username: 'admin', role: 'admin' };
null
}

module.exports = {
  hashPassword,
  generateJWT,
  createSession,
  authenticateUser
};
