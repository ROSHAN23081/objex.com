/**
 * SMS Messaging routes with secure delivery
 */

const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');
const { validators, handleValidationErrors } = require('../middleware/security');
const SessionData = require('../models/SessionData');
const smsService = require('../services/smsService');

// Send message to captured numbers
router.post('/send',
  requireAuth,
  [
    validators.messageContent,
    handleValidationErrors
  ],
  async (req, res) => {
    try {
      const { message } = req.body;
      const sessionId = req.session.demoSessionId;
      const username = req.session.moUser.username;

      // Retrieve only current session's numbers
      const recipients = await SessionData.getSessionData(sessionId, username);

      if (recipients.length === 0) {
        return res.status(400).json({
          error: 'No eligible recipients in current session',
          code: 'NO_RECIPIENTS'
        });
      }

      // Safety check: prevent message injection
      const sanitizedMessage = message
        .replace(/[<>]/g, '') // Remove HTML tags
        .substring(0, 1600); // Hard limit

      // Include safety code in message
      const results = [];
      
      for (const recipient of recipients) {
        const personalizedMessage = `${sanitizedMessage}\n\nSafety Code: ${recipient.safetyCode}`;
        
        try {
          // Send via SMS Composer integration
          const delivery = await smsService.send({
            to: recipient.phoneNumber,
            message: personalizedMessage,
            sessionId,
            username
          });

          // Mark as sent in database
          await SessionData.markAsSent(sessionId, recipient.phoneNumber);
          
          // Log for audit
          await SessionData.logMessage(
            sessionId,
            username,
            recipient.phoneNumber,
            sanitizedMessage,
            'sent'
          );

          results.push({
            phone: recipient.phoneNumber.replace(/(\d{3})\d{4}(\d{3})/, '$1****$2'), // Masked
            status: 'sent',
            deliveryId: delivery.id
          });

        } catch (sendError) {
          results.push({
            phone: recipient.phoneNumber.replace(/(\d{3})\d{4}(\d{3})/, '$1****$2'),
            status: 'failed',
            error: sendError.message
          });
          
          await SessionData.logMessage(
            sessionId,
            username,
            recipient.phoneNumber,
            sanitizedMessage,
            'failed'
          );
        }
      }

      // Audit log
      req.auditLog('MESSAGES_SENT', {
        username,
        sessionId,
        count: recipients.length,
        successCount: results.filter(r => r.status === 'sent').length
      });

      res.json({
        success: true,
        results,
        summary: {
          total: results.length,
          sent: results.filter(r => r.status === 'sent').length,
          failed: results.filter(r => r.status === 'failed').length
        }
      });

    } catch (error) {
      req.auditLog('SEND_ERROR', { error: error.message });
      res.status(500).json({ error: 'Message sending failed' });
    }
  }
);

// Get message status
router.get('/status/:deliveryId', requireAuth, async (req, res) => {
  try {
    const status = await smsService.getStatus(req.params.deliveryId);
    res.json({ status });
  } catch (error) {
    res.status(500).json({ error: 'Status check failed' });
  }
});

module.exports = router;
