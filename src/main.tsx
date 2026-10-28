import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App'
import GraphOpsDashboard from './components/watermelon/capitalio-dashboard/graphops-dashboard'
import './style.css'

const showGraphOps = new URLSearchParams(window.location.search).get('theme') === 'graphops'

createRoot(document.getElementById('app')!).render(
  <StrictMode>
    {showGraphOps ? <App /> : <GraphOpsDashboard />}
  </StrictMode>,
)
