const safeLogger = require('../utils/safeLogger');

const notFoundHandler = (req, res, next) => {
  res.status(404).json({
    success: false,
    error: `Endpoint not found: ${req.method} ${req.originalUrl}`
  });
};

const errorHandler = (err, req, res, next) => {
  safeLogger.error(`Unhandled error: ${err.message}`);

  const statusCode = err.statusCode || (res.statusCode >= 400 ? res.statusCode : 500);

  // Return clean, safe error message without leaking stack traces or internal filenames
  res.status(statusCode).json({
    success: false,
    error: err.userMessage || err.message || 'An internal server error occurred. Please try again later.'
  });
};

module.exports = {
  notFoundHandler,
  errorHandler
};
