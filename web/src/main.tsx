import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import { Analytics } from '@vercel/analytics/react';
import App from './App';
import { SessionProvider } from './context/SessionContext';
import { AnalysisProvider } from './context/AnalysisContext';
import { AlertProvider } from './context/AlertContext';
import { WaterInteraction } from './components/ui/WaterInteraction';
import './styles.css';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BrowserRouter>
      <SessionProvider>
        <AnalysisProvider>
          <AlertProvider>
            <App />
            <WaterInteraction />
            <Analytics />
          </AlertProvider>
        </AnalysisProvider>
      </SessionProvider>
    </BrowserRouter>
  </React.StrictMode>,
);
