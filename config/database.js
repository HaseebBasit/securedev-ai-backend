const mongoose = require('mongoose');

let isConnected = false;

const connectDB = async () => {
  const uri = process.env.MONGODB_URI;

  if (!uri || uri.trim() === '') {
    console.warn('[MongoDB] No MONGODB_URI provided in environment. Running in in-memory / stateless mode (Persistence disabled).');
    return false;
  }

  try {
    const conn = await mongoose.connect(uri, {
      dbName: 'securedev_ai',
      serverSelectionTimeoutMS: 5000,
    });

    isConnected = true;
    // Sanitized log: do not print host credentials
    console.log(`[MongoDB] Connected successfully to database: securedev_ai (Host: ${conn.connection.host})`);
    return true;
  } catch (error) {
    isConnected = false;
    console.error(`[MongoDB] Connection error: ${error.message}. Running in stateless mode.`);
    return false;
  }
};

const getDBStatus = () => {
  return {
    isConnected: isConnected && mongoose.connection.readyState === 1,
    readyState: mongoose.connection.readyState,
    databaseName: isConnected ? 'securedev_ai' : null
  };
};

module.exports = { connectDB, getDBStatus };
