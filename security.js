/**
 * Security configuration
 */

const cors = require('cors');

// CORS whitelist for demo
const whitelist = [
  'http://localhost:3000',
  'https://localhost:3000'
];

module.exports = {
  cors: cors({
    origin: (origin, callback) => {
      if (!origin || whitelist.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'CSRF-Token', 'X-Requested-With']
  }),

  // Password policy
  passwordPolicy: {
    minLength: 12,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: true,
    maxAge: 90 // days
  },

  // Session settings
  session: {
    idleTimeout: 30 * 60 * 1000, // 30 minutes
    absoluteTimeout: 8 * 60 * 60 * 1000 // 8 hours
  },

  // Encryption settings
  encryption: {
    algorithm: 'aes-256-gcm',
    keyRotationInterval: 24 * 60 * 60 * 1000 // 24 hours
  }
};
