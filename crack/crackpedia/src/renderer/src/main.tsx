import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import { setupConsoleBridge } from './utils/console-bridge';

// Setup console bridge - renderer logs will appear in terminal
setupConsoleBridge();

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
