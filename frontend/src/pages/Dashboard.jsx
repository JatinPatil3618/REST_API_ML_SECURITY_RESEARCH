import React, { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { booksAPI } from '../services/api'
import { useAuth } from '../context/AuthContext'

export default function Dashboard() {
  const [books, setBooks] = useState([])
  const [loading, setLoading] = useState(true)
  const { user } = useAuth()

  useEffect(() => {
    booksAPI.getAll({ limit: 50 }).then(r => {
      const myBooks = (r.data.books || []).filter(b => b.ownerUsername === user?.username)
      setBooks(myBooks)
    }).catch(() => {}).finally(() => setLoading(false))
  }, [])

  return (
    <div className="container" style={{paddingTop:'1.5rem',paddingBottom:'2rem'}}>
      <div className="flex-between page-header">
        <div>
          <h1>My Dashboard</h1>
          <p>Manage your books and activity</p>
        </div>
        <Link to="/books/new"><button className="btn btn-primary">+ Add Book</button></Link>
      </div>

      <div className="grid-3" style={{marginBottom:'1.5rem',gridTemplateColumns:'repeat(auto-fill,minmax(200px,1fr))'}}>
        <div className="stat-card"><div className="stat-label">My Books</div><div className="stat-value">{books.length}</div></div>
        <div className="stat-card"><div className="stat-label">Username</div><div className="stat-value" style={{fontSize:'1.1rem'}}>{user?.username}</div></div>
        <div className="stat-card"><div className="stat-label">Status</div><div className="stat-value" style={{fontSize:'1rem'}}><span className="badge badge-green">Active</span></div></div>
      </div>

      <div className="card">
        <h2 style={{fontSize:'1rem',fontWeight:600,marginBottom:'0.75rem'}}>My Books</h2>
        {loading ? <div><span className="spinner"></span></div> : books.length === 0 ? (
          <p style={{color:'#9ca3af'}}>No books yet. <Link to="/books/new">Add your first book →</Link></p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead><tr><th>ID</th><th>Title</th><th>Category</th><th>Rating</th><th>Actions</th></tr></thead>
              <tbody>
                {books.map(b => (
                  <tr key={b._id}>
                    <td><span className="badge badge-gray">#{b.bookId}</span></td>
                    <td><Link to={`/books/${b.bookId||b._id}`}>{b.title}</Link></td>
                    <td><span className="badge badge-blue">{b.category}</span></td>
                    <td>{b.rating}</td>
                    <td>
                      <div style={{display:'flex',gap:'0.4rem'}}>
                        <Link to={`/books/${b.bookId||b._id}/edit`}><button className="btn btn-secondary btn-sm">Edit</button></Link>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
