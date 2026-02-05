/**
 * Authentication middleware with session validation
 */

const crypto = require('crypto');
const { body, validationResult } = require('express-validator');

// Hardcoded MO users for demo (hashed passwords)
const MO_USERS = [
  {
    username: 'demo.admin',
    passwordHash: '$2b$10$YourHashedPasswordHere', // bcrypt hash
    role: 'admin',
    allowedSessions: 5
  },
  {
    username: 'demo.operator',
    passwordHash: '$2b$10$YourHashedPasswordHere',
    role: 'operator',
    allowedSessions: 3
  }
];

// Active sessions tracking (in-memory for demo, Redis in production)
const activeSessions = new Map();

/**
 * Verify MO user credentials
 */
const validateMOCredentials = async (username, password) => {
  const user = MO_USERS.find(u => u.username === username);
  if (!user) return null;
  
  const bcrypt = require('bcrypt');
  const valid = await bcrypt.compare(password, user.passwordHash);
  return valid ? user : null;
};

/**
 * Middleware: Require authentication
 */
const requireAuth = (req, res, next) => {
  if (!req.session || !req.session.moUser) {
    return res.status(401).json({ 
      error: 'Authentication required',
      code: 'AUTH_REQUIRED'
    });
  }

  // Check session validity
  if (req.session.lastActivity) {
    const idleTime = Date.now() - req.session.lastActivity;
    const MAX_IDLE = 30 * 60 * 1000; // 30 minutes
    
    if (idleTime > MAX_IDLE) {
      req.session.destroy();
      return res.status(401).json({ 
        error: 'Session expired due to inactivity',
        code: 'SESSION_EXPIRED'
      });
    }
  }

  // Update last activity
  req.session.lastActivity = Date.now();
  
  // Regenerate session ID periodically to prevent fixation
  if (!req.session.lastRegenerated || 
      Date.now() - req.session.lastRegenerated > 15 * 60 * 1000) {
    const oldSession = req.session;
    req.session.regenerate((err) => {
      if (err) return next(err);
      Object.assign(req.session, oldSession);
      req.session.lastRegenerated = Date.now();
      next();
    });
  } else {
    next();
  }
};

/**
 * Middleware: Check concurrent session limits
 */
const checkConcurrentSessions = (req, res, next) => {
  const username = req.session?.moUser?.username;
  if (!username) return next();

  const userSessions = Array.from(activeSessions.values())
    .filter(s => s.username === username && s.sessionId !== req.sessionID);

  const user = MO_USERS.find(u => u.username === username);
  if (user && userSessions.length >= user.allowedSessions) {
    return res.status(403).json({
      error: 'Maximum concurrent sessions exceeded',
      code: 'MAX_SESSIONS'
    });
  }

  // Track this session
  activeSessions.set(req.sessionID, {
    username,
    sessionId: req.sessionID,
    startedAt: Date.now(),
    ip: req.ip,
    userAgent: req.headers['user-agent']
  });

  next();
};

/**
 * Login validation rules
 */
const loginValidation = [
  body('username')
    .trim()
    .isLength({ min: 3, max: 50 })
    .matches(/^[a-zA-Z0-9._-]+$/)
    .withMessage('Invalid username format'),
  body('password')
    .isLength({ min: 8, max: 128 })
    .withMessage('Invalid password length'),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        error: 'Validation failed',
        details: errors.array() 
      });
    }
    next();
  }
];

module.exports = {
  requireAuth,
  checkConcurrentSessions,
  validateMOCredentials,
  loginValidation,
  MO_USERS,
  activeSessions
};
