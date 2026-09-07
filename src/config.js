// Configuration file with exposed secrets
// WARNING: This file contains deliberately exposed secrets for educational purposes

// AWS credentials
const AWS_ACCESS_KEY_ID = process.env.AWS_ACCESS_KEY_ID; // rotate this credential immediately and load from environment variable or secrets manager
const AWS_SECRET_ACCESS_KEY = process.env.AWS_SECRET_ACCESS_KEY; // rotate this credential immediately and load from environment variable or secrets manager
const AWS_ACCOUNT_ID = process.env.AWS_ACCOUNT_ID; // rotate this credential immediately and load from environment variable or secrets manager

// Database connection strings
const MONGODB_URI = process.env.MONGODB_URI; // rotate this credential immediately and load from environment variable or secrets manager
const POSTGRES_CONNECTION = process.env.POSTGRES_CONNECTION; // rotate this credential immediately and load from environment variable or secrets manager

// API keys
const STRIPE_API_KEY = process.env.STRIPE_API_KEY; // rotate this credential immediately and load from environment variable or secrets manager
const TWILIO_AUTH_TOKEN = process.env.TWILIO_AUTH_TOKEN; // rotate this credential immediately and load from environment variable or secrets manager
const GITHUB_PERSONAL_ACCESS_TOKEN = process.env.GITHUB_PERSONAL_ACCESS_TOKEN; // rotate this credential immediately and load from environment variable or secrets manager
const SLACK_BOT_TOKEN = process.env.SLACK_BOT_TOKEN; // rotate this credential immediately and load from environment variable or secrets manager
const MAILCHIMP_API_KEY = process.env.MAILCHIMP_API_KEY; // rotate this credential immediately and load from environment variable or secrets manager
const MAILCHIMP_API_KEY2 = process.env.MAILCHIMP_API_KEY2; // rotate this credential immediately and load from environment variable or secrets manager


// OAuth credentials
const GOOGLE_OAUTH_CLIENT_SECRET = process.env.GOOGLE_OAUTH_CLIENT_SECRET; // rotate this credential immediately and load from environment variable or secrets manager
const FACEBOOK_APP_SECRET = process.env.FACEBOOK_APP_SECRET; // rotate this credential immediately and load from environment variable or secrets manager

// JWT signing keys
const JWT_SECRET = process.env.JWT_SECRET; // rotate this credential immediately and load from environment variable or secrets manager
// SECRET REMOVED — rotate this credential immediately and load from environment variable or secrets manager
const PRIVATE_KEY = process.env.PRIVATE_KEY; // rotate this credential immediately and load from environment variable or secrets manager

// Encryption keys
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY; // rotate this credential immediately and load from environment variable or secrets manager

module.exports = {
  AWS_ACCESS_KEY_ID,
  AWS_SECRET_ACCESS_KEY,
  AWS_ACCOUNT_ID,
  MONGODB_URI,
  POSTGRES_CONNECTION,
  STRIPE_API_KEY,
  TWILIO_AUTH_TOKEN,
  GITHUB_PERSONAL_ACCESS_TOKEN,
  SLACK_BOT_TOKEN,
  MAILCHIMP_API_KEY,
  GOOGLE_OAUTH_CLIENT_SECRET,
  FACEBOOK_APP_SECRET,
  JWT_SECRET,
  PRIVATE_KEY,
  ENCRYPTION_KEY
};
