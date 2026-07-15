// Payment processing module with hardcoded API keys
// WARNING: This file contains deliberately exposed secrets for educational purposes

const stripe = require('stripe');
const process = require('process');

// SECRET REMOVED — rotate this credential immediately and load from environment variable or secrets manager
const STRIPE_TEST_KEY = process.env.STRIPE_TEST_KEY; // rotate
// SECRET REMOVED — rotate this credential immediately and load from environment variable or secrets manager
const STRIPE_LIVE_KEY = process.env.STRIPE_LIVE_KEY; // rotate
// SECRET REMOVED — rotate this credential immediately and load from environment variable or secrets manager
const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID; // rotate
// SECRET REMOVED — rotate this credential immediately and load from environment variable or secrets manager
const PAYPAL_CLIENT_SECRET = process.env.PAYPAL_CLIENT_SECRET; // rotate
// SECRET REMOVED — rotate this credential immediately and load from environment variable or secrets manager
const SQUARE_ACCESS_TOKEN = process.env.SQUARE_ACCESS_TOKEN; // rotate
// SECRET REMOVED — rotate this credential immediately and load from environment variable or secrets manager
const BRAINTREE_MERCHANT_ID = process.env.BRAINTREE_MERCHANT_ID; // rotate
// SECRET REMOVED — rotate this credential immediately and load from environment variable or secrets manager
const BRAINTREE_PUBLIC_KEY = process.env.BRAINTREE_PUBLIC_KEY; // rotate
// SECRET REMOVED — rotate this credential immediately and load from environment variable or secrets manager
const BRAINTREE_PRIVATE_KEY = process.env.BRAINTREE_PRIVATE_KEY; // rotate

// Initialize Stripe client with API key
const stripeClient = stripe(process.env.NODE_ENV === 'production' ? STRIPE_LIVE_KEY : STRIPE_TEST_KEY);

// Process payment function
async function processPayment(amount, currency, paymentMethod, cardToken) {
  try {
    const paymentIntent = await stripeClient.paymentIntents.create({
      amount,
      currency,
      payment_method: cardToken,
      confirmation_method: 'manual',
      confirm: true,
    });
    
    return {
      success: true,
      paymentId: paymentIntent.id,
      status: paymentIntent.status
    };
  } catch (error) {
    console.error('Payment processing error:', error);
    return {
      success: false,
      error: error.message
    };
  }
}

module.exports = {
  processPayment,
  // Exposing API keys for demonstration purposes (bad practice)
  apiKeys: {
    stripe: {
      test: STRIPE_TEST_KEY,
      live: STRIPE_LIVE_KEY
    },
    paypal: {
      clientId: PAYPAL_CLIENT_ID,
      clientSecret: PAYPAL_CLIENT_SECRET
    },
    square: SQUARE_ACCESS_TOKEN,
    braintree: {
      merchantId: BRAINTREE_MERCHANT_ID,
      publicKey: BRAINTREE_PUBLIC_KEY,
      privateKey: BRAINTREE_PRIVATE_KEY
    }
  }
};
