/**
 * Security middleware: input validation, sanitization, XSS protection
 */

const { body, param, validationResult } = require('express-validator');
const xss = require('xss');

// XSS sanitization
const sanitizeInput = (input) => {
  if (typeof input === 'string') {
    return xss(input, {
      whiteList: {}, // No HTML allowed
      stripIgnoreTag: true,
      stripIgnoreTagBody: ['script']
    });
  }
  return input;
};

// Deep sanitize object
const deepSanitize = (obj) => {
  if (Array.isArray(obj)) {
    return obj.map(deepSanitize);
  }
  if (obj && typeof obj === 'object') {
    const sanitized = {};
    for (const [key, value] of Object.entries(obj)) {
      sanitized[key] = deepSanitize(value);
    }
    return sanitized;
  }
  return sanitizeInput(obj);
};

const securityMiddleware = (req, res, next) => {
  // Sanitize all input
  if (req.body) req.body = deepSanitize(req.body);
  if (req.query) req.query = deepSanitize(req.query);
  if (req.params) req.params = deepSanitize(req.params);

  // Add security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');

  next();
};

// Validation schemas
const validators = {
  phoneNumber: body('phoneNumber')
    .trim()
    .matches(/^\+?[1-9]\d{1,14}$/)
    .withMessage('Invalid phone number format (E.164 required)'),
  
  safetyCode: body('safetyCode')
    .trim()
    .isLength({ min: 6, max: 20 })
    .matches(/^[A-Z0-9-]+$/)
    .withMessage('Safety code must be 6-20 alphanumeric characters'),
  
  messageContent: body('message')
    .trim()
    .isLength({ min: 1, max: 1600 }) // SMS segment limit
    .withMessage('Message must be 1-1600 characters')
};

const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: 'Validation failed',
      details: errors.array().map(e => ({
        field: e.path,
        message: e.msg
      }))
    });
  }
  next();
};

module.exports = {
  securityMiddleware,
  validators,
  handleValidationErrors,
  sanitizeInput
};
