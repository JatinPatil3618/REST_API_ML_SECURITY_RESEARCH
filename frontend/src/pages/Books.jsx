import React, { useState, useEffect } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { booksAPI } from '../services/api'
import { useAuth } from '../context/AuthContext'

export default function Books() {
  const [books, setBooks] = useState([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [category, setCategory] = useState('')
  const [page, setPage] = useState(1)
  const [pagination, setPagination] = useState({})
  const { user, isLoggedIn } = useAuth()
  const nav = useNavigate()

  useEffect(() => { fetchBooks() }, [page])

  const fetchBooks = async (s=search, c=category) => {
    setLoading(true)
    try {
      const res = await booksAPI.getAll({ search: s, category: c, page, limit: 20 })
      setBooks(res.data.books || [])
      setPagination(res.data.pagination || {})
    } catch { setBooks([]) }
    finally { setLoading(false) }
  }

  const handleSearch = (e) => { e.preventDefault(); setPage(1); fetchBooks() }

  const handleDelete = async (id) => {
    if (!confirm('Delete this book?')) return
    try {
      await booksAPI.delete(id)
      setBooks(books.filter(b => (b.bookId || b._id) != id))
    } catch (err) {
      alert(err.response?.data?.error || 'Delete failed')
    }
  }

  return (
    <div className="container" style={{paddingTop:'1.5rem',paddingBottom:'2rem'}}>
      <div className="flex-between page-header">
        <div>
          <h1>Books</h1>
          <p>Browse the collection · {pagination.total || 0} total</p>
        </div>
        {isLoggedIn && <button className="btn btn-primary" onClick={() => nav('/books/new')}>+ Add Book</button>}
      </div>

      <form onSubmit={handleSearch} style={{display:'flex',gap:'0.75rem',marginBottom:'1.25rem',flexWrap:'wrap'}}>
        <input className="form-control" style={{flex:1,minWidth:200}} placeholder="Search…" value={search}
          onChange={e => setSearch(e.target.value)} />
        <select className="form-control" style={{width:160}} value={category}
          onChange={e => setCategory(e.target.value)}>
          <option value="">All categories</option>
          {['Technology','Science','Fiction','History','Business','Arts'].map(c => <option key={c}>{c}</option>)}
        </select>
        <button className="btn btn-primary" type="submit">Search</button>
        <button className="btn btn-secondary" type="button" onClick={() => { setSearch(''); setCategory(''); fetchBooks('','') }}>Clear</button>
      </form>

      {loading ? (
        <div style={{textAlign:'center',padding:'2rem',color:'#6b7280'}}><span className="spinner"></span> Loading…</div>
      ) : (
        <>
          <div className="table-wrap card" style={{padding:0}}>
            <table>
              <thead>
                <tr>
                  <th>ID</th><th>Title</th><th>Author</th><th>Category</th>
                  <th>Owner</th><th>Rating</th><th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {books.map(b => (
                  <tr key={b._id}>
                    <td><span className="badge badge-gray">#{b.bookId}</span></td>
                    <td><Link to={`/books/${b.bookId || b._id}`}>{b.title}</Link></td>
                    <td>{b.author}</td>
                    <td><span className="badge badge-blue">{b.category}</span></td>
                    <td>{b.ownerUsername}</td>
                    <td style={{color:'#f59e0b'}}>{'★'.repeat(Math.round(b.rating))}</td>
                    <td>
                      <div style={{display:'flex',gap:'0.4rem'}}>
                        <Link to={`/books/${b.bookId || b._id}`}><button className="btn btn-secondary btn-sm">View</button></Link>
                        {isLoggedIn && user?.username === b.ownerUsername && <>
                          <button className="btn btn-secondary btn-sm" onClick={() => nav(`/books/${b.bookId || b._id}/edit`)}>Edit</button>
                          <button className="btn btn-danger btn-sm" onClick={() => handleDelete(b.bookId || b._id)}>Delete</button>
                        </>}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {pagination.pages > 1 && (
            <div style={{display:'flex',gap:'0.5rem',marginTop:'1rem',justifyContent:'center'}}>
              {Array.from({length: pagination.pages}, (_, i) => i+1).map(p => (
                <button key={p} className={`btn btn-sm ${p===page?'btn-primary':'btn-secondary'}`}
                  onClick={() => setPage(p)}>{p}</button>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  )
}
