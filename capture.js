/**
 * Phone number and safety code capture routes
 */

const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');
const { validators, handleValidationErrors } = require('../middleware/security');
const SessionData = require('../models/SessionData');

// Capture phone and safety code
router.post('/',
  requireAuth,
  [
    validators.phoneNumber,
    body('confirmPhoneNumber')
      .custom((value, { req }) => {
        if (value !== req.body.phoneNumber) {
          throw new Error('Phone numbers do not match');
        }
        return true;
      }),
    validators.safetyCode,
    body('confirmSafetyCode')
      .custom((value, { req }) => {
        if (value !== req.body.safetyCode) {
          throw new Error('Safety codes do not match');
        }
        return true;
      }),
    handleValidationErrors
  ],
  async (req, res) => {
    try {
      const { phoneNumber, safetyCode } = req.body;
      const sessionId = req.session.demoSessionId;
      const username = req.session.moUser.username;

      // Double-entry verification already done in validation
      
      // Store encrypted
      await SessionData.captureData(sessionId, phoneNumber, safetyCode);

      // Audit log
      req.auditLog('DATA_CAPTURED', {
        username,
        sessionId,
        phoneHash: require('crypto')
          .createHash('sha256')
          .update(phoneNumber)
          .digest('hex')
          .substring(0, 16) // Log only hash for privacy
      });

      res.json({
        success: true,
        message: 'Information captured securely',
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      req.auditLog('CAPTURE_ERROR', { error: error.message });
      res.status(500).json({ error: 'Failed to capture data' });
    }
  }
);

// Get current session captures (for messaging page)
router.get('/current', requireAuth, async (req, res) => {
  try {
    const sessionId = req.session.demoSessionId;
    const username = req.session.moUser.username;

    const data = await SessionData.getSessionData(sessionId, username);

    res.json({
      success: true,
      captures: data,
      count: data.length,
      sessionActive: true
    });

  } catch (error) {
    res.status(500).json({ error: 'Failed to retrieve session data' });
  }
});

module.exports = router;
