'use client';

import { useState } from 'react';
import { createRoot } from 'react-dom/client';
import { FluentProvider, webDarkTheme, webLightTheme } from '@fluentui/react-components';
import { LockerApp } from './locker-app.jsx';
import './global.css';

function AppRoot() {
  const [mode, setMode] = useState('light');
  const theme = mode === 'dark' ? webDarkTheme : webLightTheme;

  return (
    <FluentProvider theme={theme}>
      <LockerApp
        mode={mode}
        onToggleTheme={() => setMode((current) => (current === 'light' ? 'dark' : 'light'))}
      />
    </FluentProvider>
  );
}

createRoot(document.getElementById('root')).render(<AppRoot />);
