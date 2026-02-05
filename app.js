/**
 * Mobile Objex Secure Demo Server
 * Enterprise-grade security implementation
 */

require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const csrf = require('csurf');
const path = require('path');
const winston = require('winston');

const securityConfig = require('./config/security');
const authRoutes = require('./routes/auth');
const captureRoutes = require('./routes/capture');
const messagingRoutes = require('./routes/messaging');
const auditRoutes = require('./routes/audit');
const { securityMiddleware } = require('./middleware/security');
const { rateLimiter } = require('./middleware/rateLimiter');
const auditLogger = require('./middleware/auditLogger');

// Security audit logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/security-audit.log' }),
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.Console()
  ]
});

const app = express();
const PORT = process.env.PORT || 3000;

// Trust proxy for secure cookies behind reverse proxy
app.set('trust proxy', 1);

// Security headers with Helmet
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"], // Allow inline for demo styling
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"]
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

// Body parsing with size limits
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// CORS configuration
app.use(securityConfig.cors);

// Global rate limiting
app.use(rateLimiter.general);

// Session configuration with SQLite store
const sessionMiddleware = session({
  store: new SQLiteStore({
    db: 'sessions.db',
    dir: './data',
    concurrentDB: true
  }),
  secret: process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex'),
  name: 'mo.sid', // Change from default connect.sid
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 30 * 60 * 1000, // 30 minutes
    sameSite: 'strict',
    domain: process.env.COOKIE_DOMAIN || undefined
  },
  rolling: true // Refresh expiry on activity
});

app.use(sessionMiddleware);

// CSRF protection
const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  }
});

// Apply CSRF to all routes except specific exemptions
app.use((req, res, next) => {
  // Exempt health checks but nothing else
  if (req.path === '/health') return next();
  csrfProtection(req, res, next);
});

// Security middleware (input sanitization, etc.)
app.use(securityMiddleware);

// Audit logging
app.use(auditLogger(logger));

// Static files
app.use(express.static(path.join(__dirname, '../client')));

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/capture', captureRoutes);
app.use('/api/messaging', messagingRoutes);
app.use('/api/audit', auditRoutes);

// CSRF token endpoint for frontend
app.get('/api/csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// Error handling
app.use((err, req, res, next) => {
  logger.error('Security error:', {
    error: err.message,
    path: req.path,
    ip: req.ip,
    timestamp: new Date().toISOString()
  });

  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ 
      error: 'Invalid security token. Please refresh the page.' 
    });
  }

  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Resource not found' });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully');
  process.exit(0);
});

app.listen(PORT, () => {
  logger.info(`Mobile Objex Secure Demo running on port ${PORT}`);
  console.log(`🔒 Secure server running at http://localhost:${PORT}`);
  console.log(`📋 Audit logs: ./logs/security-audit.log`);
});

module.exports = app;
