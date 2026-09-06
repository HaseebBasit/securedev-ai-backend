/**
 * Safe logging utility ensuring no sensitive credentials, secrets, or uploaded code are leaked to console/logs.
 */

const SENSITIVE_PATTERNS = [
  /mongodb(\+srv)?:\/\/[^@]+@/gi,
  /bearer\s+[a-zA-Z0-9_\-\.]+/gi,
  /(api[_-]?key|secret|password|auth[_-]?token)["']?\s*[:=]\s*["']?([^"',\s]+)/gi
];

const maskSensitiveData = (message) => {
  if (typeof message !== 'string') {
    try {
      message = JSON.stringify(message);
    } catch {
      return '[Unparseable Data]';
    }
  }

  let sanitized = message;
  // Mask MongoDB URI credentials
  sanitized = sanitized.replace(/mongodb(\+srv)?:\/\/[^@]+@/gi, 'mongodb$1://***:***@');
  // Mask Bearer tokens
  sanitized = sanitized.replace(/bearer\s+[a-zA-Z0-9_\-\.]+/gi, 'Bearer ***');
  // Mask API keys & secrets
  sanitized = sanitized.replace(/(api[_-]?key|secret|password|token)["']?\s*[:=]\s*["']?([^"',\s]+)/gi, '$1="***"');

  return sanitized;
};

const safeLogger = {
  info: (...args) => {
    const sanitized = args.map(arg => (typeof arg === 'string' ? maskSensitiveData(arg) : arg));
    console.log('[INFO]', ...sanitized);
  },
  warn: (...args) => {
    const sanitized = args.map(arg => (typeof arg === 'string' ? maskSensitiveData(arg) : arg));
    console.warn('[WARN]', ...sanitized);
  },
  error: (...args) => {
    const sanitized = args.map(arg => (typeof arg === 'string' ? maskSensitiveData(arg) : arg));
    console.error('[ERROR]', ...sanitized);
  },
  audit: (action, meta = {}) => {
    // Safe audit logging: log only metadata (e.g. language, length, status), never the raw code
    const safeMeta = { ...meta };
    delete safeMeta.code;
    delete safeMeta.sourceCode;
    console.log(`[AUDIT] Action: ${action} | Meta:`, JSON.stringify(safeMeta));
  }
};

module.exports = safeLogger;
