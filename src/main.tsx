import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';

// Self-hosted via Fontsource — no external <link>, no render-blocking fetch.
import '@fontsource-variable/space-grotesk';
import '@fontsource/jetbrains-mono/400.css';
import '@fontsource/jetbrains-mono/500.css';

import './index.css';

const container = document.getElementById('root');
if (!container) throw new Error('Root element #root not found');

createRoot(container).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
