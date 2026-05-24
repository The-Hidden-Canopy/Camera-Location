#!/usr/bin/env python3
"""Replace the Camera Viewer block in app.js using safe fragment matching."""
import pathlib, sys

APP_JS = pathlib.Path(r'E:\HiddenCanopy\Camera-Location\camdiscover\web\static\js\app.js')

content = APP_JS.read_text(encoding='utf-8')

# Find the start of the Camera Viewer comment line
cam_idx = content.find('Camera Viewer')
if cam_idx == -1:
    sys.exit('ERROR: "Camera Viewer" not found in file')
# Walk back to start of line
line_start = content.rfind('\n', 0, cam_idx) + 1   # +1 to skip the \n

# Find the Set IP Dialog comment line (our end marker)
set_ip_idx = content.find('Set IP Dialog', cam_idx)
if set_ip_idx == -1:
    sys.exit('ERROR: "Set IP Dialog" not found after Camera Viewer section')
# Walk back to start of that line
end_line_start = content.rfind('\n', 0, set_ip_idx) + 1
# We want to end just before that blank+comment, i.e., at the \n before it
# Actually: preserve the blank line + "Set IP Dialog" comment — just cut up to end_line_start
si = line_start
ei = end_line_start

print(f'Replacing chars {si}..{ei} ({ei-si} chars)')

NEW_BLOCK = '''  // ─── Camera Viewer ──────────────────────────────────────────────────────
  window._viewCamera = async function(ip) {
    const device = devices.find(d => d.ip === ip) || { ip };

    // Load saved credentials
    let savedUser = 'admin', savedPass = '';
    try {
      const credsResp = await fetch(`/api/devices/${encodeURIComponent(ip)}/credentials`);
      if (credsResp.ok) {
        const creds = await credsResp.json();
        savedUser = creds.username || 'admin';
        savedPass = creds.password || '';
      }
    } catch(e) { /* use defaults */ }

    const html = `<div class="cam__viewer-overlay" id="viewer-overlay" onclick="if(event.target===this)window._closeViewer()">
      <div class="cam__viewer">
        <div class="cam__viewer__header">
          <span class="cam__viewer__title">&#128247; ${esc(ip)} &mdash; ${esc(device.vendor || 'Camera')}</span>
          <button class="cam__viewer__close" onclick="window._closeViewer()">&times;</button>
        </div>
        <div class="cam__viewer__snapshot-wrap" id="viewer-snap-wrap">
          <img id="viewer-img" class="cam__viewer__img" src="" alt="Loading...">
          <div class="cam__viewer__snap-error" id="viewer-snap-error" style="display:none">
            No image available — check credentials or camera may use RTSP only.
          </div>
        </div>
        <div class="cam__viewer__controls">
          <button class="cam__viewer__btn cam__viewer__btn--active" id="viewer-btn-snap" onclick="window._setViewerMode('${esc(ip)}','snap')">&#9634; Snapshot</button>
          <button class="cam__viewer__btn" id="viewer-btn-live" onclick="window._setViewerMode('${esc(ip)}','live')">&#9654; Live</button>
          ${device.rtsp_url ? `<button class="cam__viewer__btn" onclick="navigator.clipboard.writeText('${esc(device.rtsp_url)}').then(()=>addActivityEvent('found','RTSP copied'))">&#128203; Copy RTSP</button>` : ''}
          ${device.web_url ? `<a class="cam__viewer__btn" href="${esc(device.web_url)}" target="_blank">&#127760; Web UI</a>` : ''}
          <button class="cam__viewer__btn" id="viewer-onvif-btn-${esc(ip)}" onclick="window._queryOnvifInfo('${esc(ip)}')">&#9881; ONVIF Info</button>
          <button class="cam__viewer__btn cam__viewer__btn--setip" onclick="window._closeViewer();window._showSetIPDialog('${esc(ip)}')">&#9998; Change IP</button>
        </div>
        <div class="cam__viewer__info" id="viewer-info-${esc(ip)}">
          ${device.rtsp_url ? `<div class="cam__viewer__info-row"><span class="cam__viewer__info-label">RTSP</span><code>${esc(device.rtsp_url)}</code></div>` : ''}
          ${device.onvif_url ? `<div class="cam__viewer__info-row"><span class="cam__viewer__info-label">ONVIF</span><code>${esc(device.onvif_url)}</code></div>` : ''}
          <div class="cam__viewer__info-row"><span class="cam__viewer__info-label">MAC</span><code>${esc(device.mac || '—')}</code></div>
          <div class="cam__viewer__info-row"><span class="cam__viewer__info-label">Ports</span><code>${(device.open_ports || []).join(', ') || '—'}</code></div>
          ${device.firmware ? `<div class="cam__viewer__info-row"><span class="cam__viewer__info-label">FW</span><code>${esc(device.firmware)}</code></div>` : ''}
        </div>
        <div class="cam__viewer__auth">
          <span class="cam__viewer__auth-label">Credentials</span>
          <input type="text"     id="viewer-user" placeholder="username" value="${esc(savedUser)}" class="cam__viewer__auth-input">
          <input type="password" id="viewer-pass" placeholder="password" value="${esc(savedPass)}" class="cam__viewer__auth-input">
          <button class="cam__viewer__btn" onclick="window._saveAndLoad('${esc(ip)}')">&#128190; Save &amp; Load</button>
          <button class="cam__viewer__btn" onclick="window._refreshSnapshot('${esc(ip)}')">&#8635; Snap</button>
        </div>
      </div>
    </div>`;

    closeAnyDialog();
    document.body.insertAdjacentHTML('beforeend', html);
    window._setViewerMode(ip, 'snap');
  };

  window._closeViewer = function() {
    const overlay = document.getElementById('viewer-overlay');
    if (!overlay) return;
    const img = document.getElementById('viewer-img');
    if (img) img.src = '';   // stop MJPEG stream
    overlay.remove();
  };

  window._saveAndLoad = async function(ip) {
    const user = (document.getElementById('viewer-user') || {}).value || 'admin';
    const pass = (document.getElementById('viewer-pass') || {}).value || '';
    try {
      await fetch(`/api/devices/${encodeURIComponent(ip)}/credentials`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: user, password: pass })
      });
      addActivityEvent('found', `Credentials saved for ${ip}`);
    } catch(e) {
      addActivityEvent('error', `Failed to save credentials for ${ip}`);
    }
    const liveBtn = document.getElementById('viewer-btn-live');
    const mode = liveBtn && liveBtn.classList.contains('cam__viewer__btn--active') ? 'live' : 'snap';
    window._setViewerMode(ip, mode);
  };

  window._setViewerMode = function(ip, mode) {
    const img     = document.getElementById('viewer-img');
    const errEl   = document.getElementById('viewer-snap-error');
    const snapBtn = document.getElementById('viewer-btn-snap');
    const liveBtn = document.getElementById('viewer-btn-live');
    if (!img) return;

    if (snapBtn) snapBtn.classList.toggle('cam__viewer__btn--active', mode === 'snap');
    if (liveBtn) liveBtn.classList.toggle('cam__viewer__btn--active', mode === 'live');

    const user = (document.getElementById('viewer-user') || {}).value || 'admin';
    const pass = (document.getElementById('viewer-pass') || {}).value || '';

    if (mode === 'live') {
      img.src = '';
      if (errEl) errEl.style.display = 'none';
      img.style.opacity = '0.4';
      const streamUrl = `/api/devices/${encodeURIComponent(ip)}/stream?user=${encodeURIComponent(user)}&pass=${encodeURIComponent(pass)}`;
      img.onload  = () => { img.style.opacity = '1'; };
      img.onerror = () => {
        img.style.opacity = '0';
        if (errEl) errEl.style.display = '';
        if (liveBtn) liveBtn.classList.remove('cam__viewer__btn--active');
        if (snapBtn) snapBtn.classList.add('cam__viewer__btn--active');
      };
      img.src = streamUrl;
    } else {
      img.src = '';   // stop any live stream first
      window._refreshSnapshot(ip);
    }
  };

  window._queryOnvifInfo = async function(ip) {
    const btn    = document.getElementById(`viewer-onvif-btn-${ip}`);
    const infoEl = document.getElementById(`viewer-info-${ip}`);
    if (btn) { btn.disabled = true; btn.textContent = 'Querying…'; }
    const user = (document.getElementById('viewer-user') || {}).value || 'admin';
    const pass = (document.getElementById('viewer-pass') || {}).value || '';
    try {
      const resp = await fetch(`/api/devices/${encodeURIComponent(ip)}/onvif-info?user=${encodeURIComponent(user)}&pass=${encodeURIComponent(pass)}`);
      const info = await resp.json();
      if (info.error) {
        addActivityEvent('error', `ONVIF info failed for ${ip}: ${info.error}`);
      } else {
        const d = devices.find(x => x.ip === ip);
        if (d) {
          if (info.model)    d.model    = info.model;
          if (info.firmware) d.firmware = info.firmware;
          if (info.stream_uris && info.stream_uris.length) d.rtsp_url = info.stream_uris[0];
          renderTable();
        }
        if (infoEl) {
          let extra = '';
          if (info.manufacturer) extra += `<div class="cam__viewer__info-row"><span class="cam__viewer__info-label">Mfr</span><code>${esc(info.manufacturer)}</code></div>`;
          if (info.model)        extra += `<div class="cam__viewer__info-row"><span class="cam__viewer__info-label">Model</span><code>${esc(info.model)}</code></div>`;
          if (info.firmware)     extra += `<div class="cam__viewer__info-row"><span class="cam__viewer__info-label">FW</span><code>${esc(info.firmware)}</code></div>`;
          if (info.serial)       extra += `<div class="cam__viewer__info-row"><span class="cam__viewer__info-label">S/N</span><code>${esc(info.serial)}</code></div>`;
          (info.stream_uris || []).forEach((u, i) => {
            extra += `<div class="cam__viewer__info-row"><span class="cam__viewer__info-label">Stream ${i+1}</span><code>${esc(u)}</code> <button class="cam__viewer__btn" style="padding:1px 6px;font-size:10px" onclick="navigator.clipboard.writeText('${esc(u)}').then(()=>addActivityEvent('found','RTSP copied'))">Copy</button></div>`;
          });
          infoEl.insertAdjacentHTML('beforeend', extra);
        }
        addActivityEvent('found', `ONVIF info: ${ip} — ${info.manufacturer} ${info.model} FW:${info.firmware}`);
      }
    } catch(e) {
      addActivityEvent('error', `ONVIF info error for ${ip}`);
    }
    if (btn) { btn.disabled = false; btn.innerHTML = '&#9881; ONVIF Info'; }
  };

  window._refreshSnapshot = function(ip) {
    const img   = document.getElementById('viewer-img');
    const errEl = document.getElementById('viewer-snap-error');
    if (!img) return;
    const user = (document.getElementById('viewer-user') || {}).value || 'admin';
    const pass = (document.getElementById('viewer-pass') || {}).value || '';
    const ts   = Date.now();
    const url  = `/api/devices/${encodeURIComponent(ip)}/snapshot?user=${encodeURIComponent(user)}&pass=${encodeURIComponent(pass)}&_=${ts}`;
    img.src = '';
    img.style.opacity = '0.4';
    if (errEl) errEl.style.display = 'none';
    const tester = new Image();
    tester.onload  = () => { img.src = url; img.style.opacity = '1'; };
    tester.onerror = () => { img.style.opacity = '0'; if (errEl) errEl.style.display = ''; };
    tester.src = url;
  };

'''

result = content[:si] + NEW_BLOCK + content[ei:]
APP_JS.write_text(result, encoding='utf-8')
print(f'Done. File is now {len(result)} chars.')
