import React, { useState, useEffect } from 'react'
import { useNavigate, useParams, Link } from 'react-router-dom'
import { booksAPI } from '../services/api'

const CATEGORIES = ['Technology', 'Science', 'Fiction', 'History', 'Business', 'Arts', 'Other']

export default function EditBook() {
  const { id } = useParams()
  const [form, setForm] = useState({ title: '', author: '', category: '', description: '', rating: 0 })
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const nav = useNavigate()

  useEffect(() => {
    booksAPI.getById(id).then(r => {
      const b = r.data.book
      setForm({ title: b.title, author: b.author, category: b.category, description: b.description || '', rating: b.rating })
    }).catch(e => setError(e.response?.data?.error || 'Load failed'))
    .finally(() => setLoading(false))
  }, [id])

  const set = k => e => setForm(p => ({...p, [k]: e.target.value}))

  const handleSubmit = async (e) => {
    e.preventDefault(); setError(''); setSaving(true)
    try {
      await booksAPI.update(id, form)
      nav(`/books/${id}`)
    } catch (err) {
      setError(err.response?.data?.error || 'Update failed')
    } finally { setSaving(false) }
  }

  if (loading) return <div style={{textAlign:'center',padding:'2rem'}}><span className="spinner"></span></div>

  return (
    <div className="container" style={{paddingTop:'1.5rem',paddingBottom:'2rem',maxWidth:600}}>
      <Link to={`/books/${id}`} style={{fontSize:'0.875rem',color:'#6b7280'}}>← Back</Link>
      <div className="card mt-2">
        <h1 style={{fontSize:'1.3rem',fontWeight:700,marginBottom:'1.25rem'}}>Edit Book</h1>
        {error && <div className="alert alert-error">{error}</div>}
        <form onSubmit={handleSubmit}>
          <div className="form-group"><label className="form-label">Title</label>
            <input className="form-control" value={form.title} onChange={set('title')} required /></div>
          <div className="form-group"><label className="form-label">Author</label>
            <input className="form-control" value={form.author} onChange={set('author')} required /></div>
          <div className="grid-2">
            <div className="form-group"><label className="form-label">Category</label>
              <select className="form-control" value={form.category} onChange={set('category')}>
                {CATEGORIES.map(c => <option key={c}>{c}</option>)}
              </select></div>
            <div className="form-group"><label className="form-label">Rating</label>
              <input className="form-control" type="number" min={0} max={5} step={0.5} value={form.rating} onChange={set('rating')} /></div>
          </div>
          <div className="form-group"><label className="form-label">Description</label>
            <textarea className="form-control" rows={4} value={form.description} onChange={set('description')} /></div>
          <div style={{display:'flex',gap:'0.75rem'}}>
            <button className="btn btn-primary" disabled={saving}>{saving ? 'Saving…' : 'Save Changes'}</button>
            <button className="btn btn-secondary" type="button" onClick={() => nav(`/books/${id}`)}>Cancel</button>
          </div>
        </form>
      </div>
    </div>
  )
}
