const mongoose = require('mongoose');

// Vulnerability 20: Hardcoded credentials and no TLS
const dbUri = 'mongodb://admin:password123@localhost:27017/vulnerable_db';

// Connect without TLS/SSL
function connectToDatabase() {
  mongoose.connect(dbUri, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('Connected to database'))
    .catch(err => console.error('Database connection error:', err));
}

// Vulnerability 21: No input sanitization for database queries
async function findUserByUsername(username) {
  // Direct string interpolation in query - NoSQL injection risk
  const query = { username: username };
  return await mongoose.model('User').findOne(query);
}

// Vulnerability 22: Exposing sensitive data in error messages
function handleDatabaseError(err, res) {
  // Exposing detailed error information to clients
  return res.status(500).json({
    error: 'Database error occurred',
    details: err.toString(),
    stack: err.stack
  });
}

module.exports = {
  connectToDatabase,
  findUserByUsername,
  handleDatabaseError
};
