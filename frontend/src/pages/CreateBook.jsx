import React, { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { booksAPI } from '../services/api'

const CATEGORIES = ['Technology', 'Science', 'Fiction', 'History', 'Business', 'Arts', 'Other']

export default function CreateBook() {
  const [form, setForm] = useState({ title: '', author: '', category: 'Technology', description: '', rating: 3 })
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const nav = useNavigate()

  const set = k => e => setForm(p => ({...p, [k]: e.target.value}))

  const handleSubmit = async (e) => {
    e.preventDefault(); setError(''); setLoading(true)
    try {
      const res = await booksAPI.create(form)
      nav(`/books/${res.data.book.bookId || res.data.book._id}`)
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to create book')
    } finally { setLoading(false) }
  }

  return (
    <div className="container" style={{paddingTop:'1.5rem',paddingBottom:'2rem',maxWidth:600}}>
      <Link to="/books" style={{fontSize:'0.875rem',color:'#6b7280'}}>← Back to Books</Link>
      <div className="card mt-2">
        <h1 style={{fontSize:'1.3rem',fontWeight:700,marginBottom:'1.25rem'}}>Add New Book</h1>
        {error && <div className="alert alert-error">{error}</div>}
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label">Title *</label>
            <input className="form-control" value={form.title} onChange={set('title')} required />
          </div>
          <div className="form-group">
            <label className="form-label">Author *</label>
            <input className="form-control" value={form.author} onChange={set('author')} required />
          </div>
          <div className="grid-2">
            <div className="form-group">
              <label className="form-label">Category</label>
              <select className="form-control" value={form.category} onChange={set('category')}>
                {CATEGORIES.map(c => <option key={c}>{c}</option>)}
              </select>
            </div>
            <div className="form-group">
              <label className="form-label">Rating (0–5)</label>
              <input className="form-control" type="number" min={0} max={5} step={0.5} value={form.rating} onChange={set('rating')} />
            </div>
          </div>
          <div className="form-group">
            <label className="form-label">Description</label>
            <textarea className="form-control" rows={4} value={form.description} onChange={set('description')} />
          </div>
          <div style={{display:'flex',gap:'0.75rem'}}>
            <button className="btn btn-primary" disabled={loading}>{loading ? 'Creating…' : 'Create Book'}</button>
            <button className="btn btn-secondary" type="button" onClick={() => nav('/books')}>Cancel</button>
          </div>
        </form>
      </div>
    </div>
  )
}
