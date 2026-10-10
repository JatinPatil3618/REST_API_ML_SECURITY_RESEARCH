import React from 'react'
import { NavLink, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'

export default function Navbar() {
  const { user, isLoggedIn, logout } = useAuth()
  const nav = useNavigate()

  const handleLogout = () => { logout(); nav('/login') }

  return (
    <nav className="navbar">
      <div className="container navbar-inner">
        <NavLink to="/" className="navbar-brand" style={{textDecoration:'none'}}>
          Secure<span>Book</span> <span style={{fontSize:'0.7rem',color:'#9ca3af',fontWeight:400}}>API Lab</span>
        </NavLink>

        <div className="navbar-links">
          <NavLink to="/" className={({isActive})=>`nav-link${isActive?' active':''}`} end>Home</NavLink>
          <NavLink to="/books" className={({isActive})=>`nav-link${isActive?' active':''}`}>Books</NavLink>
          {isLoggedIn && <>
            <NavLink to="/dashboard" className={({isActive})=>`nav-link${isActive?' active':''}`}>My Dashboard</NavLink>
            <NavLink to="/profile" className={({isActive})=>`nav-link${isActive?' active':''}`}>Profile</NavLink>
            <NavLink to="/security-lab" className={({isActive})=>`nav-link${isActive?' active':''}`}>Security Lab</NavLink>
            <NavLink to="/history" className={({isActive})=>`nav-link${isActive?' active':''}`}>Request History</NavLink>
          </>}
          <NavLink to="/about" className={({isActive})=>`nav-link${isActive?' active':''}`}>About</NavLink>
        </div>

        <div className="nav-user">
          {isLoggedIn ? (
            <>
              <span style={{fontSize:'0.85rem',color:'#374151'}}>👤 {user?.username}</span>
              <button className="btn-logout" onClick={handleLogout}>Sign out</button>
            </>
          ) : (
            <NavLink to="/login"><button className="btn btn-primary btn-sm">Sign in</button></NavLink>
          )}
        </div>
      </div>
    </nav>
  )
}
