/**
 * Deterministic seed script.
 * Creates 5 users (user01–user05) each with 2 books (deterministic IDs 101–502).
 * This ownership mapping is critical for BOLA experiments.
 */
require('dotenv').config({ path: require('path').join(__dirname, '../../.env') });
const mongoose = require('mongoose');
const User = require('../models/User');
const Book = require('../models/Book');
const Comment = require('../models/Comment');

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/securebook_research';

const SEED_USERS = [
  { username: 'user01', email: 'user01@securebook.lab', password: 'User01Pass!', seededId: 1 },
  { username: 'user02', email: 'user02@securebook.lab', password: 'User02Pass!', seededId: 2 },
  { username: 'user03', email: 'user03@securebook.lab', password: 'User03Pass!', seededId: 3 },
  { username: 'user04', email: 'user04@securebook.lab', password: 'User04Pass!', seededId: 4 },
  { username: 'user05', email: 'user05@securebook.lab', password: 'User05Pass!', seededId: 5 },
];

// Deterministic book data — ownership tied to seededId
const BOOK_DATA = [
  // user01 books
  { bookId: 101, title: 'Introduction to Computer Networks', author: 'James F. Kurose', category: 'Technology', description: 'A comprehensive guide to modern networking concepts and protocols.', ownerIdx: 0, rating: 4.5 },
  { bookId: 102, title: 'Clean Code', author: 'Robert C. Martin', category: 'Technology', description: 'A handbook of agile software craftsmanship covering principles of clean code.', ownerIdx: 0, rating: 4.8 },
  // user02 books
  { bookId: 201, title: 'The Pragmatic Programmer', author: 'David Thomas', category: 'Technology', description: 'A guide from journeyman to master, covering practical programming techniques.', ownerIdx: 1, rating: 4.7 },
  { bookId: 202, title: 'Design Patterns', author: 'Gang of Four', category: 'Technology', description: 'Elements of reusable object-oriented software patterns.', ownerIdx: 1, rating: 4.6 },
  // user03 books
  { bookId: 301, title: 'A Brief History of Time', author: 'Stephen Hawking', category: 'Science', description: 'An exploration of cosmology, black holes, and the nature of time.', ownerIdx: 2, rating: 4.9 },
  { bookId: 302, title: 'The Selfish Gene', author: 'Richard Dawkins', category: 'Science', description: 'A revolutionary view of evolution from the gene-centric perspective.', ownerIdx: 2, rating: 4.4 },
  // user04 books
  { bookId: 401, title: 'Sapiens', author: 'Yuval Noah Harari', category: 'History', description: 'A brief history of humankind from the Stone Age to the present.', ownerIdx: 3, rating: 4.8 },
  { bookId: 402, title: 'The Art of War', author: 'Sun Tzu', category: 'History', description: 'Ancient Chinese military treatise on strategy and tactics.', ownerIdx: 3, rating: 4.3 },
  // user05 books
  { bookId: 501, title: 'Zero to One', author: 'Peter Thiel', category: 'Business', description: 'Notes on startups, or how to build the future.', ownerIdx: 4, rating: 4.2 },
  { bookId: 502, title: 'The Lean Startup', author: 'Eric Ries', category: 'Business', description: 'How entrepreneurs use continuous innovation to create successful businesses.', ownerIdx: 4, rating: 4.5 },
];

const SEED_COMMENTS = [
  { bookId: 101, authorIdx: 1, content: 'Excellent resource for understanding TCP/IP and modern networking.' },
  { bookId: 101, authorIdx: 2, content: 'The diagrams and examples make complex concepts approachable.' },
  { bookId: 201, authorIdx: 0, content: 'Every developer should read this. Changed how I think about software.' },
  { bookId: 301, authorIdx: 3, content: 'Hawking explains the universe in a way anyone can understand.' },
  { bookId: 401, authorIdx: 4, content: 'A thought-provoking journey through human history.' },
  { bookId: 501, authorIdx: 2, content: 'Thiel\'s perspective on innovation is both unique and compelling.' },
];

const seed = async () => {
  try {
    await mongoose.connect(MONGO_URI);
    console.log('[Seed] Connected to MongoDB');

    // Clear existing seed data
    await User.deleteMany({ seededId: { $exists: true, $ne: null } });
    console.log('[Seed] Cleared existing seeded users');

    // Create users
    const createdUsers = [];
    for (const userData of SEED_USERS) {
      const user = new User(userData);
      await user.save();
      createdUsers.push(user);
      console.log(`[Seed] Created ${user.username} (${user._id})`);
    }

    // Delete seeded books
    await Book.deleteMany({ bookId: { $gte: 101, $lte: 502 } });

    // Create books with deterministic ownership
    for (const bookData of BOOK_DATA) {
      const owner = createdUsers[bookData.ownerIdx];
      await Book.create({
        bookId: bookData.bookId,
        title: bookData.title,
        author: bookData.author,
        category: bookData.category,
        description: bookData.description,
        owner: owner._id,
        ownerUsername: owner.username,
        rating: bookData.rating
      });
      console.log(`[Seed] Book ${bookData.bookId} "${bookData.title}" -> ${owner.username}`);
    }

    // Create comments
    for (const commentData of SEED_COMMENTS) {
      const book = await Book.findOne({ bookId: commentData.bookId });
      const author = createdUsers[commentData.authorIdx];
      if (book && author) {
        await Comment.create({
          bookId: book._id,
          author: author._id,
          authorUsername: author.username,
          content: commentData.content
        });
      }
    }

    console.log('\n[Seed] === OWNERSHIP MAP (for BOLA experiments) ===');
    console.log('user01: books 101, 102');
    console.log('user02: books 201, 202');
    console.log('user03: books 301, 302');
    console.log('user04: books 401, 402');
    console.log('user05: books 501, 502');
    console.log('\n[Seed] === TEST CREDENTIALS ===');
    for (const u of SEED_USERS) {
      console.log(`  ${u.username} / ${u.password}`);
    }
    console.log('\n[Seed] Complete.');
    process.exit(0);
  } catch (err) {
    console.error('[Seed] Error:', err.message);
    process.exit(1);
  }
};

seed();
