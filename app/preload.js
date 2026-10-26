const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('deepguard', {
  status: () => ipcRenderer.invoke('status'),
  diagnostics: () => ipcRenderer.invoke('diagnostics'),
  events: () => ipcRenderer.invoke('events'),
  scan: data => ipcRenderer.invoke('scan', data),
  toggleAutoProxy: () => ipcRenderer.invoke('toggle-autoproxy'),
  repairNetwork: () => ipcRenderer.invoke('repair-network'),
  openChatGPT: () => ipcRenderer.invoke('open-chatgpt'),
  openClaude: () => ipcRenderer.invoke('open-claude'),
  onEvents: cb => ipcRenderer.on('events:update', (_, e) => cb(e)),
  onStatus: cb => ipcRenderer.on('status:update', (_, e) => cb(e))
});
