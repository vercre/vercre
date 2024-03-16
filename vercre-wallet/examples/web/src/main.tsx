import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.tsx'

import { ViewStateProvider } from './ViewState'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
      <ViewStateProvider>
        <App />
      </ViewStateProvider>
  </React.StrictMode>,
);
