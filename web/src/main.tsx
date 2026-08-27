import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import { Analytics } from '@vercel/analytics/react';
import App from './App';
import { SessionProvider } from './context/SessionContext';
import { AnalysisProvider } from './context/AnalysisContext';
import { AlertProvider } from './context/AlertContext';
import './styles.css';

document.documentElement.dataset.visualMode = localStorage.getItem('sentineltrace_visual_mode') || 'balanced';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BrowserRouter>
      <SessionProvider>
        <AnalysisProvider>
          <AlertProvider>
            <App />
            <Analytics />
          </AlertProvider>
        </AnalysisProvider>
      </SessionProvider>
    </BrowserRouter>
  </React.StrictMode>,
);
