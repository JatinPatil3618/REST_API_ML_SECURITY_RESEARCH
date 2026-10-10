import React, { useState, useEffect } from 'react'
import { profileAPI } from '../services/api'
import { useAuth } from '../context/AuthContext'

export default function Profile() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const { user } = useAuth()

  useEffect(() => {
    profileAPI.get().then(r => setData(r.data)).catch(() => {}).finally(() => setLoading(false))
  }, [])

  if (loading) return <div style={{textAlign:'center',padding:'2rem'}}><span className="spinner"></span></div>

  return (
    <div className="container" style={{paddingTop:'1.5rem',paddingBottom:'2rem',maxWidth:700}}>
      <div className="page-header"><h1>Profile</h1><p>Your account details and activity</p></div>

      <div className="card mb-2">
        <div style={{display:'flex',alignItems:'center',gap:'1rem'}}>
          <div style={{width:56,height:56,borderRadius:'50%',background:'#dbeafe',display:'flex',alignItems:'center',justifyContent:'center',fontSize:'1.4rem'}}>
            {user?.username?.[0]?.toUpperCase() || '?'}
          </div>
          <div>
            <div style={{fontWeight:700,fontSize:'1.1rem'}}>{data?.user?.username || user?.username}</div>
            <div style={{color:'#6b7280',fontSize:'0.875rem'}}>{data?.user?.email}</div>
            <div style={{color:'#9ca3af',fontSize:'0.8rem'}}>Member since {data?.user?.createdAt ? new Date(data.user.createdAt).toLocaleDateString() : 'N/A'}</div>
          </div>
        </div>
      </div>

      <div className="grid-2 mb-2">
        <div className="stat-card">
          <div className="stat-label">Books</div>
          <div className="stat-value">{data?.stats?.bookCount ?? 0}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Comments</div>
          <div className="stat-value">{data?.stats?.commentCount ?? 0}</div>
        </div>
      </div>

      {data?.recentRequests?.length > 0 && (
        <div className="card">
          <h2 style={{fontSize:'1rem',fontWeight:600,marginBottom:'0.75rem'}}>Recent Activity</h2>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Method</th><th>Endpoint</th><th>Status</th><th>Time</th></tr></thead>
              <tbody>
                {data.recentRequests.slice(0,10).map(r => (
                  <tr key={r._id}>
                    <td><span className={`badge ${r.method==='GET'?'badge-blue':r.method==='POST'?'badge-green':'badge-yellow'}`}>{r.method}</span></td>
                    <td style={{fontSize:'0.8rem',fontFamily:'monospace'}}>{r.endpoint}</td>
                    <td><span className={`badge ${r.statusCode<400?'badge-green':'badge-red'}`}>{r.statusCode}</span></td>
                    <td style={{fontSize:'0.75rem',color:'#9ca3af'}}>{new Date(r.timestamp).toLocaleTimeString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
