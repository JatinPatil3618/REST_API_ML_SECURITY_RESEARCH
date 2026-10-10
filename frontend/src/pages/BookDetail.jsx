import React, { useState, useEffect } from 'react'
import { useParams, Link, useNavigate } from 'react-router-dom'
import { booksAPI, commentsAPI } from '../services/api'
import { useAuth } from '../context/AuthContext'

export default function BookDetail() {
  const { id } = useParams()
  const [book, setBook] = useState(null)
  const [comments, setComments] = useState([])
  const [newComment, setNewComment] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [commentError, setCommentError] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const { user, isLoggedIn } = useAuth()
  const nav = useNavigate()

  useEffect(() => { fetchBook(); fetchComments() }, [id])

  const fetchBook = async () => {
    setLoading(true); setError('')
    try {
      const res = await booksAPI.getById(id)
      setBook(res.data.book)
    } catch (err) {
      setError(err.response?.data?.error || 'Book not found.')
    } finally { setLoading(false) }
  }

  const fetchComments = async () => {
    try {
      const res = await commentsAPI.getByBook(id)
      setComments(res.data.comments || [])
    } catch { setComments([]) }
  }

  const handleAddComment = async (e) => {
    e.preventDefault(); setCommentError(''); setSubmitting(true)
    try {
      const res = await commentsAPI.add(id, { content: newComment })
      setComments(c => [res.data.comment, ...c])
      setNewComment('')
    } catch (err) {
      const msg = err.response?.data?.error || 'Failed to add comment'
      if (msg.includes('blocked') || err.response?.status === 403) {
        setCommentError('⚠️ Unsafe input blocked by security gateway.')
      } else {
        setCommentError(msg)
      }
    } finally { setSubmitting(false) }
  }

  const handleDelete = async () => {
    if (!confirm('Delete this book?')) return
    try {
      await booksAPI.delete(id)
      nav('/books')
    } catch (err) {
      alert(err.response?.data?.error || 'Delete failed')
    }
  }

  if (loading) return <div style={{textAlign:'center',padding:'3rem'}}><span className="spinner"></span></div>
  if (error) return (
    <div className="container" style={{paddingTop:'2rem'}}>
      <div className="alert alert-error">{error}</div>
      <Link to="/books">← Back to Books</Link>
    </div>
  )

  return (
    <div className="container" style={{paddingTop:'1.5rem',paddingBottom:'2rem',maxWidth:800}}>
      <Link to="/books" style={{fontSize:'0.875rem',color:'#6b7280'}}>← Back to Books</Link>

      <div className="card mt-2">
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start',flexWrap:'wrap',gap:'1rem'}}>
          <div>
            <div style={{display:'flex',gap:'0.5rem',alignItems:'center',marginBottom:'0.5rem'}}>
              <span className="badge badge-blue">{book.category}</span>
              <span className="badge badge-gray">Book #{book.bookId}</span>
            </div>
            <h1 style={{fontSize:'1.5rem',fontWeight:700}}>{book.title}</h1>
            <p style={{color:'#6b7280',marginTop:'0.25rem'}}>by <strong>{book.author}</strong></p>
          </div>
          {isLoggedIn && user?.username === book.ownerUsername && (
            <div style={{display:'flex',gap:'0.5rem'}}>
              <button className="btn btn-secondary btn-sm" onClick={() => nav(`/books/${id}/edit`)}>Edit</button>
              <button className="btn btn-danger btn-sm" onClick={handleDelete}>Delete</button>
            </div>
          )}
        </div>

        <hr style={{margin:'1rem 0',borderColor:'#f3f4f6'}} />

        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:'0.75rem',marginBottom:'1rem',fontSize:'0.875rem'}}>
          <div><span style={{color:'#9ca3af'}}>Owner:</span> <strong>{book.ownerUsername}</strong></div>
          <div><span style={{color:'#9ca3af'}}>Rating:</span> <span style={{color:'#f59e0b'}}>{'★'.repeat(Math.round(book.rating))}{'☆'.repeat(5-Math.round(book.rating))}</span> ({book.rating})</div>
          <div><span style={{color:'#9ca3af'}}>Added:</span> {new Date(book.createdAt).toLocaleDateString()}</div>
        </div>

        <p style={{color:'#374151',lineHeight:1.7}}>{book.description || 'No description available.'}</p>
      </div>

      {/* Comments */}
      <div className="card mt-2">
        <h2 style={{fontSize:'1.1rem',fontWeight:600,marginBottom:'1rem'}}>Comments ({comments.length})</h2>

        {isLoggedIn && (
          <form onSubmit={handleAddComment} style={{marginBottom:'1.25rem'}}>
            {commentError && <div className="alert alert-warning" style={{marginBottom:'0.5rem'}}>{commentError}</div>}
            <textarea className="form-control" rows={3} value={newComment}
              onChange={e => setNewComment(e.target.value)}
              placeholder="Write a comment…" required style={{resize:'vertical'}} />
            <button className="btn btn-primary btn-sm mt-1" disabled={submitting}>
              {submitting ? <><span className="spinner"></span> Posting…</> : 'Post comment'}
            </button>
          </form>
        )}

        {comments.length === 0 ? (
          <p style={{color:'#9ca3af',fontSize:'0.875rem'}}>No comments yet. Be the first!</p>
        ) : (
          <div style={{display:'flex',flexDirection:'column',gap:'0.75rem'}}>
            {comments.map(c => (
              <div key={c._id} style={{padding:'0.75rem',background:'#f9fafb',borderRadius:6,border:'1px solid #f3f4f6'}}>
                <div style={{display:'flex',justifyContent:'space-between',marginBottom:'0.4rem'}}>
                  <strong style={{fontSize:'0.85rem'}}>{c.authorUsername}</strong>
                  <span style={{fontSize:'0.75rem',color:'#9ca3af'}}>{new Date(c.createdAt).toLocaleDateString()}</span>
                </div>
                <p style={{fontSize:'0.875rem',color:'#374151'}}
                   dangerouslySetInnerHTML={{__html: c.content.replace(/</g,'&lt;').replace(/>/g,'&gt;')}} />
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
