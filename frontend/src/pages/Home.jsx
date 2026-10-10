import React, { useState, useEffect } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { booksAPI } from '../services/api'
import { useAuth } from '../context/AuthContext'

const CATEGORIES = ['Technology', 'Science', 'Fiction', 'History', 'Business', 'Arts']

function BookCard({ book }) {
  return (
    <Link to={`/books/${book.bookId || book._id}`} style={{textDecoration:'none'}}>
      <div className="book-card">
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start'}}>
          <span className="book-id">#{book.bookId}</span>
          <span className="category-tag">{book.category}</span>
        </div>
        <h3>{book.title}</h3>
        <p className="author">by {book.author}</p>
        <p style={{fontSize:'0.8rem',color:'#6b7280',overflow:'hidden',display:'-webkit-box',WebkitLineClamp:2,WebkitBoxOrient:'vertical'}}>
          {book.description}
        </p>
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginTop:'auto'}}>
          <span className="owner-tag">📚 {book.ownerUsername}</span>
          <span style={{fontSize:'0.8rem',color:'#f59e0b'}}>{'★'.repeat(Math.round(book.rating))}{'☆'.repeat(5-Math.round(book.rating))}</span>
        </div>
      </div>
    </Link>
  )
}

export default function Home() {
  const [books, setBooks] = useState([])
  const [search, setSearch] = useState('')
  const [category, setCategory] = useState('')
  const [loading, setLoading] = useState(true)
  const { isLoggedIn } = useAuth()
  const nav = useNavigate()

  useEffect(() => { fetchBooks() }, [])

  const fetchBooks = async (s='', c='') => {
    setLoading(true)
    try {
      const res = await booksAPI.getAll({ search: s, category: c, limit: 12 })
      setBooks(res.data.books || [])
    } catch { setBooks([]) }
    finally { setLoading(false) }
  }

  const handleSearch = (e) => {
    e.preventDefault()
    fetchBooks(search, category)
  }

  return (
    <div style={{minHeight:'calc(100vh - 56px)'}}>
      {/* Hero */}
      <div style={{background:'linear-gradient(135deg,#1e3a5f 0%,#2563eb 100%)',color:'#fff',padding:'3rem 0'}}>
        <div className="container">
          <h1 style={{fontSize:'2rem',fontWeight:800,marginBottom:'0.5rem'}}>SecureBook API Lab</h1>
          <p style={{opacity:0.85,maxWidth:520,marginBottom:'1.5rem'}}>
            A book management platform with real-time ML-based API security monitoring.
            Browse books, add comments, and explore the security research features.
          </p>
          {!isLoggedIn && (
            <div style={{display:'flex',gap:'0.75rem'}}>
              <button className="btn" style={{background:'#fff',color:'#1e3a5f',fontWeight:600}}
                onClick={() => nav('/login')}>Sign In</button>
              <button className="btn" style={{background:'rgba(255,255,255,0.15)',color:'#fff',border:'1px solid rgba(255,255,255,0.4)'}}
                onClick={() => nav('/register')}>Register</button>
            </div>
          )}
        </div>
      </div>

      <div className="container" style={{paddingTop:'1.5rem',paddingBottom:'2rem'}}>
        {/* Search */}
        <div className="card mb-2">
          <form onSubmit={handleSearch} style={{display:'flex',gap:'0.75rem',flexWrap:'wrap'}}>
            <input className="form-control" style={{flex:'1',minWidth:200}}
              placeholder="Search books by title, author…" value={search}
              onChange={e => setSearch(e.target.value)} />
            <select className="form-control" style={{width:160}} value={category}
              onChange={e => { setCategory(e.target.value); fetchBooks(search, e.target.value) }}>
              <option value="">All categories</option>
              {CATEGORIES.map(c => <option key={c}>{c}</option>)}
            </select>
            <button className="btn btn-primary" type="submit">Search</button>
            {isLoggedIn && (
              <button className="btn btn-secondary" type="button" onClick={() => nav('/books/new')}>
                + Add Book
              </button>
            )}
          </form>
        </div>

        {/* Featured categories */}
        <div style={{display:'flex',gap:'0.5rem',flexWrap:'wrap',marginBottom:'1.25rem'}}>
          <span style={{fontSize:'0.875rem',color:'#6b7280',alignSelf:'center'}}>Browse:</span>
          {CATEGORIES.map(c => (
            <button key={c} className={`btn btn-sm ${category===c?'btn-primary':'btn-secondary'}`}
              onClick={() => { setCategory(c); fetchBooks(search, c) }}>
              {c}
            </button>
          ))}
          {category && <button className="btn btn-sm btn-secondary" onClick={() => { setCategory(''); fetchBooks(search,'') }}>Clear</button>}
        </div>

        {/* Books grid */}
        <div className="page-header">
          <div className="flex-between">
            <h1>{category || 'All Books'} {books.length > 0 && `(${books.length})`}</h1>
            <Link to="/books" style={{fontSize:'0.875rem'}}>View all →</Link>
          </div>
        </div>

        {loading ? (
          <div style={{textAlign:'center',padding:'3rem',color:'#6b7280'}}>
            <span className="spinner"></span> Loading books…
          </div>
        ) : books.length === 0 ? (
          <div className="card" style={{textAlign:'center',padding:'2rem',color:'#6b7280'}}>
            No books found. {isLoggedIn && <Link to="/books/new">Add the first one →</Link>}
          </div>
        ) : (
          <div className="grid-3" style={{gridTemplateColumns:'repeat(auto-fill,minmax(280px,1fr))'}}>
            {books.map(b => <BookCard key={b._id} book={b} />)}
          </div>
        )}
      </div>
    </div>
  )
}
