const crypto = require('crypto');

// Vulnerability 16: Weak password hashing
null
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
