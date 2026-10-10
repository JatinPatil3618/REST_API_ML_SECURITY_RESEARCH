import axios from 'axios'

// All requests go through Gateway (port 8080), not directly to demo API
const api = axios.create({
  baseURL: 'http://localhost:8080',
  timeout: 10000,
})

// Attach JWT token to every request
api.interceptors.request.use(cfg => {
  const token = localStorage.getItem('token')
  if (token) cfg.headers.Authorization = `Bearer ${token}`
  return cfg
})

// Handle 401 globally
api.interceptors.response.use(
  res => res,
  err => {
    if (err.response?.status === 401) {
      localStorage.removeItem('token')
      localStorage.removeItem('user')
      window.location.href = '/login'
    }
    return Promise.reject(err)
  }
)

export const authAPI = {
  login: (data) => api.post('/api/auth/login', data),
  register: (data) => api.post('/api/auth/register', data),
}

export const booksAPI = {
  getAll: (params) => api.get('/api/books', { params }),
  getById: (id) => api.get(`/api/books/${id}`),
  create: (data) => api.post('/api/books', data),
  update: (id, data) => api.put(`/api/books/${id}`, data),
  delete: (id) => api.delete(`/api/books/${id}`),
}

export const commentsAPI = {
  getByBook: (bookId) => api.get(`/api/comments/book/${bookId}`),
  add: (bookId, data) => api.post(`/api/comments/book/${bookId}`, data),
}

export const profileAPI = {
  get: () => api.get('/api/profile'),
  getHistory: (params) => api.get('/api/users/me/requests', { params }),
}

export const gatewayAPI = {
  health: () => api.get('/api/health'),
}

export default api
