const mongoose = require('mongoose');

const bookSchema = new mongoose.Schema({
  bookId: { type: Number, unique: true, index: true },  // deterministic: 101-502
  title: { type: String, required: true, trim: true },
  author: { type: String, required: true, trim: true },
  category: {
    type: String,
    enum: ['Technology', 'Science', 'Fiction', 'History', 'Business', 'Arts', 'Other'],
    default: 'Other'
  },
  description: { type: String, trim: true },
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  ownerUsername: { type: String, required: true },
  rating: { type: Number, min: 0, max: 5, default: 0 },
  isPublic: { type: Boolean, default: true }
}, { timestamps: true });

module.exports = mongoose.model('Book', bookSchema);
