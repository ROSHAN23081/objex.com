/**
 * Authentication routes with security hardening
 */

const express = require('express');
const bcrypt = require('bcrypt');
const router = express.Router();
const { requireAuth, validateMOCredentials, loginValidation, activeSessions } = require('../middleware/auth');
const { rateLimiter } = require('../middleware/rateLimiter');
const SessionData = require('../models/SessionData');

// Login route with brute force protection
router.post('/login', 
  rateLimiter.login,
  loginValidation,
  async (req, res) => {
    try {
      const { username, password } = req.body;
      const ip = req.ip;
      const userAgent = req.headers['user-agent'];

      // Validate credentials
      const user = await validateMOCredentials(username, password);
      
      if (!user) {
        // Log failed attempt
        req.auditLog('LOGIN_FAILED', { username, ip, reason: 'Invalid credentials' });
        
        // Generic error to prevent user enumeration
        return res.status(401).json({ 
          error: 'Invalid credentials',
          code: 'AUTH_FAILED'
        });
      }

      // Regenerate session to prevent fixation
      req.session.regenerate(async (err) => {
        if (err) {
          return res.status(500).json({ error: 'Session creation failed' });
        }

        // Create MO demo session in database
        const demoSession = await SessionData.createSession(req.sessionID, username);

        // Set session data
        req.session.moUser = {
          username: user.username,
          role: user.role,
          sessionStart: new Date().toISOString()
        };
        req.session.demoSessionId = demoSession.sessionId;
        req.session.lastActivity = Date.now();
        req.session.lastRegenerated = Date.now();

        // Log success
        req.auditLog('LOGIN_SUCCESS', { 
          username, 
          role: user.role,
          sessionId: req.sessionID 
        });

        res.json({
          success: true,
          username: user.username,
          role: user.role,
          csrfToken: req.csrfToken()
        });
      });

    } catch (error) {
      req.auditLog('LOGIN_ERROR', { error: error.message });
      res.status(500).json({ error: 'Authentication system error' });
    }
  }
);

// Logout route with complete cleanup
router.post('/logout', requireAuth, async (req, res) => {
  try {
    const username = req.session.moUser?.username;
    const sessionId = req.session.demoSessionId;

    // Purge all session data from database
    if (sessionId) {
      await SessionData.endSession(sessionId);
    }

    // Remove from active sessions tracking
    activeSessions.delete(req.sessionID);

    // Audit log
    req.auditLog('LOGOUT', { username, sessionId });

    // Destroy session
    req.session.destroy((err) => {
      if (err) {
        return res.status(500).json({ error: 'Logout failed' });
      }
      
      res.clearCookie('mo.sid');
      res.json({ success: true, message: 'Logged out and session data purged' });
    });

  } catch (error) {
    res.status(500).json({ error: 'Logout error' });
  }
});

// Session status check
router.get('/status', requireAuth, (req, res) => {
  res.json({
    authenticated: true,
    username: req.session.moUser.username,
    role: req.session.moUser.role,
    sessionStart: req.session.moUser.sessionStart,
    csrfToken: req.csrfToken()
  });
});

module.exports = router;
