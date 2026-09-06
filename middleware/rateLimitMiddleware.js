const rateLimit = require('express-rate-limit');

const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute window
  max: 60, // Limit each IP to 60 requests per minute
  standardHeaders: true, // Return rate limit info in `RateLimit-*` headers
  legacyHeaders: false, // Disable `X-RateLimit-*` headers
  message: {
    success: false,
    error: 'Too many requests from this IP, please try again after 1 minute.'
  }
});

const analyzeLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute window
  max: 30, // Limit analyze endpoint to 30 requests per minute
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: 'Rate limit exceeded for code analysis. Please wait a moment before submitting more code.'
  }
});

module.exports = {
  apiLimiter,
  analyzeLimiter
};
