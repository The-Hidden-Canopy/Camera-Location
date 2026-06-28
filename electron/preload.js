const { contextBridge, ipcRenderer } = require('electron');

/**
 * Preload script — Camera Discovery Octopus
 * Exposes safe IPC bridge for desktop features and authenticated backend fetch.
 */

let _backendUrl = '';
let _backendToken = '';

async function refreshSecrets() {
  const secrets = await ipcRenderer.invoke('app:getBackendSecrets');
  _backendUrl = secrets.url || '';
  _backendToken = secrets.token || '';
  return secrets;
}

// Initial fetch
refreshSecrets();

contextBridge.exposeInMainWorld('electronAPI', {
  // Window controls
  minimize: () => ipcRenderer.invoke('app:minimize'),
  maximize: () => ipcRenderer.invoke('app:maximize'),
  close: () => ipcRenderer.invoke('app:close'),
  isMaximized: () => ipcRenderer.invoke('app:isMaximized'),

  // Flask backend
  getFlaskUrl: () => ipcRenderer.invoke('app:getFlaskUrl'),
  restartFlask: () => ipcRenderer.invoke('app:restartFlask'),

  // Authenticated fetch helper
  getBackendSecrets: refreshSecrets,
  fetch: (endpoint, options = {}) => {
    const url = endpoint.startsWith('http') ? endpoint : `${_backendUrl}${endpoint}`;
    const headers = options.headers || {};
    if (_backendToken) {
      headers['X-Backend-Token'] = _backendToken;
    }
    return fetch(url, { ...options, headers });
  },

  // Platform info
  platform: process.platform,
  isElectron: true,
});
