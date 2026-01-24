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

  // In development, we need to point to the backend URL explicitly.
  // In production (served by .NET), the Blazor app is at the root.
  // You can override this in dev by setting VITE_BLAZOR_APP_URL (e.g. http://localhost:5041/).
  const blazorAppUrl = import.meta.env.DEV
    ? (import.meta.env.VITE_BLAZOR_APP_URL ?? 'http://localhost:5041/')
    : '/'

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
            <div style={{ display: 'flex', gap: '10px', justifyContent: 'center', marginBottom: '10px' }}>
              <button onClick={logout}>Logout</button>
              <a href={blazorAppUrl} className="button-link" style={{ 
                display: 'inline-block', 
                padding: '0.6em 1.2em', 
                border: '1px solid transparent', 
                borderRadius: '8px', 
                backgroundColor: '#1a1a1a', 
                color: 'white', 
                textDecoration: 'none', 
                fontSize: '1em', 
                fontFamily: 'inherit',
                cursor: 'pointer',
                transition: 'border-color 0.25s'
              }}>Go to Blazor App</a>
            </div>
          </div>
        ) : (
          <button onClick={login}>Login</button>
        )}
      </header>
    </div>
  )
}

export default App