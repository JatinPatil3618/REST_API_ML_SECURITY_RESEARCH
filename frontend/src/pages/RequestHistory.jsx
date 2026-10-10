import React, { useState, useEffect } from 'react'
import { profileAPI } from '../services/api'

export default function RequestHistory() {
  const [requests, setRequests] = useState([])
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)

  useEffect(() => {
    profileAPI.getHistory({ page, limit: 30 }).then(r => {
      setRequests(r.data.requests || [])
      setTotal(r.data.pagination?.total || 0)
    }).catch(() => {}).finally(() => setLoading(false))
  }, [page])

  return (
    <div className="container" style={{paddingTop:'1.5rem',paddingBottom:'2rem'}}>
      <div className="page-header">
        <h1>Request History</h1>
        <p>Your recent API requests — {total} total</p>
      </div>

      {loading ? <div style={{textAlign:'center',padding:'2rem'}}><span className="spinner"></span></div> : (
        <div className="card" style={{padding:0}}>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Time</th><th>Method</th><th>Endpoint</th><th>Status</th><th>Latency</th><th>Request ID</th></tr></thead>
              <tbody>
                {requests.map(r => (
                  <tr key={r._id}>
                    <td style={{fontSize:'0.8rem',color:'#6b7280'}}>{new Date(r.timestamp).toLocaleString()}</td>
                    <td><span className={`badge ${r.method==='GET'?'badge-blue':r.method==='POST'?'badge-green':r.method==='DELETE'?'badge-red':'badge-yellow'}`}>{r.method}</span></td>
                    <td style={{fontFamily:'monospace',fontSize:'0.8rem'}}>{r.endpoint}</td>
                    <td><span className={`badge ${r.statusCode<400?'badge-green':'badge-red'}`}>{r.statusCode}</span></td>
                    <td style={{fontSize:'0.8rem'}}>{r.responseTimeMs}ms</td>
                    <td style={{fontSize:'0.7rem',color:'#9ca3af',fontFamily:'monospace'}}>{r.requestId?.substring(0,12)}…</td>
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
