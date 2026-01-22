import { useEffect, useState } from 'react'
import './App.css'

interface UserInfo {
  isAuthenticated: boolean
  name?: string
  claims?: Record<string, string>
}

function App() {
  const [user, setUser] = useState<UserInfo>({ isAuthenticated: false })
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch('/api/user')
      .then(res => res.json())
      .then(data => setUser(data))
      .catch(() => setUser({ isAuthenticated: false }))
      .finally(() => setLoading(false))
  }, [])

  const login = () => {
    window.location.href = '/authentication/login?returnUrl=' + encodeURIComponent(window.location.href)
  }

  const logout = () => {
    window.location.href = '/authentication/logout?returnUrl=' + encodeURIComponent(window.location.href)
  }

  if (loading) {
    return <div className="loading">Loading...</div>
  }

  return (
    <div className="app">
      <header className="app-header">
        <h1>IDP Testing - React Frontend</h1>
        {user.isAuthenticated ? (
          <div className="user-info">
            <p>Welcome, {user.name}!</p>
            <button onClick={logout}>Logout</button>
          </div>
        ) : (
          <button onClick={login}>Login</button>
        )}
      </header>
    </div>
  )
}

export default App