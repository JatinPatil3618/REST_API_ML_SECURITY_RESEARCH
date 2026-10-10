const mongoose = require('mongoose');

const connectDB = async () => {
  const uri = process.env.MONGO_URI || 'mongodb://localhost:27017/securebook_research';
  try {
    await mongoose.connect(uri);
    console.log(`[MongoDB] Connected: ${uri}`);
  } catch (err) {
    console.error('[MongoDB] Connection failed:', err.message);
    process.exit(1);
  }
};

module.exports = connectDB;
