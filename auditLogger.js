/**
 * Security audit logging middleware
 */

const auditLogger = (logger) => {
  return (req, res, next) => {
    req.auditLog = (action, details = {}) => {
      const logEntry = {
        timestamp: new Date().toISOString(),
        action,
        user: req.session?.moUser?.username || 'anonymous',
        sessionId: req.sessionID || 'none',
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        path: req.path,
        method: req.method,
        ...details
      };

      logger.info('AUDIT', logEntry);
    };

    // Log all requests
    const start = Date.now();
    res.on('finish', () => {
      const duration = Date.now() - start;
      req.auditLog('REQUEST', {
        statusCode: res.statusCode,
        duration,
        contentLength: res.get('content-length')
      });
    });

    next();
  };
};

module.exports = auditLogger;
