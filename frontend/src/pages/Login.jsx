import React, { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { authAPI } from '../services/api'

export default function Login() {
  const [form, setForm] = useState({ username: '', password: '' })
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const { login } = useAuth()
  const nav = useNavigate()

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError(''); setLoading(true)
    try {
      const res = await authAPI.login(form)
      login(res.data.user, res.data.token)
      nav('/')
    } catch (err) {
      setError(err.response?.data?.error || 'Login failed. Please try again.')
    } finally { setLoading(false) }
  }

  const fillDemo = (u, p) => setForm({ username: u, password: p })

  return (
    <div className="auth-page">
      <div className="auth-card">
        <h1>Welcome back</h1>
        <p>Sign in to your SecureBook account</p>

        {error && <div className="alert alert-error">{error}</div>}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label">Username or Email</label>
            <input className="form-control" value={form.username}
              onChange={e => setForm(p => ({...p, username: e.target.value}))}
              placeholder="user01" autoFocus required />
          </div>
          <div className="form-group">
            <label className="form-label">Password</label>
            <input className="form-control" type="password" value={form.password}
              onChange={e => setForm(p => ({...p, password: e.target.value}))}
              placeholder="••••••••" required />
          </div>
          <button className="btn btn-primary" style={{width:'100%'}} disabled={loading}>
            {loading ? <><span className="spinner"></span> Signing in…</> : 'Sign in'}
          </button>
        </form>

        <div className="auth-divider">— Demo accounts —</div>
        <div style={{display:'flex',gap:'0.4rem',flexWrap:'wrap',justifyContent:'center'}}>
          {['01','02','03','04','05'].map(n => (
            <button key={n} className="btn btn-secondary btn-sm"
              onClick={() => fillDemo(`user${n}`, `User${n}Pass!`)}>
              user{n}
            </button>
          ))}
        </div>
        <p style={{textAlign:'center',marginTop:'1rem',fontSize:'0.875rem',color:'#6b7280'}}>
          Don't have an account? <Link to="/register">Register</Link>
        </p>
      </div>
    </div>
  )
}
