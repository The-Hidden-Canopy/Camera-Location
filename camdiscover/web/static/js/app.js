/**
 * app.js — Camera Discovery Octopus
 * Frontend dashboard: SSE live updates, scan control, device table,
 * DPI protocol-stage validation, subnet zones, capture position,
 * detail panel, filtering, and export.
 */

(function() {
  'use strict';

  // ─── Utilities ──────────────────────────────────────────────────────
  const esc = (t) => String(t == null ? '' : t)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

  // ─── State ──────────────────────────────────────────────────────────
  let devices = [];
  let liveDevices = [];
  let persistedInventory = [];
  let sites = [];
  let currentSiteId = '';
  let inventoryMode = 'live';
  let selectedDeviceIp = null;
  let currentMode = 'listen';
  let isScanning = false;
  let scanStartTime = null;
  let scanTimer = null;
  let sortField = 'ip';
  let sortDir = 'asc';
  let eventSource = null;
  let activityEvents = [];
  let subnetZones = [];
  let capturePosition = { position: 'ethernet_same', can_see_unicast: true, can_see_rtsp: true };
  let isWatching = false;
  let sniffedSubnets = [];   // subnets detected by the sniffer
  let viewerPasswordCache = {}; // ip -> password (renderer memory only)

  // DPI stage order for display
  const DPI_STAGES = ['link','dhcp','discovery','auth','rtsp','onvif_ctrl','ntp','dns','cloud','recording'];
  const DPI_LABELS = {
    link:'L2',dhcp:'DHCP',discovery:'Disc',auth:'Auth',rtsp:'RTSP',
    onvif_ctrl:'ONVIF',ntp:'NTP',dns:'DNS',cloud:'Cloud',recording:'Rec'
  };

  // ─── DOM refs ───────────────────────────────────────────────────────
  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => document.querySelectorAll(sel);
  const on = (el, event, handler) => {
    if (!el) return false;
    el.addEventListener(event, handler);
    return true;
  };

  async function apiFetch(endpoint, options = {}) {
    const response = window.electronAPI && window.electronAPI.fetch
      ? await window.electronAPI.fetch(endpoint, options)
      : await fetch(endpoint, options);
    if (!response.ok) {
      let detail = '';
      try {
        const body = await response.clone().json();
        detail = body.error || body.detail || '';
      } catch (_) { /* non-JSON error response */ }
      throw new Error(detail || `API request failed (${response.status})`);
    }
    return response;
  }

  async function authenticatedMediaUrl(endpoint) {
    if (!window.electronAPI || !window.electronAPI.getBackendSecrets) return endpoint;
    const secrets = await window.electronAPI.getBackendSecrets();
    const url = new URL(endpoint, secrets.url || window.location.origin);
    if (secrets.token) url.searchParams.set('backend_token', secrets.token);
    return url.toString();
  }

  async function downloadExport(endpoint, filename) {
    try {
      const response = await apiFetch(endpoint);
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    } catch (error) {
      addActivityEvent('error', error.message || `Export failed: ${filename}`);
    }
  }

  function displayDeviceType(device) {
    if (device && device.asset_class === 'workstation') return 'computer';
    return (device && (device.device_type || device.device_class)) || 'unknown';
  }

  const app = $('#app');
  const ifaceSelect = $('#iface-select');
  const siteSelect = $('#site-select');
  const inventoryToggle = $('#inventory-toggle');
  const modeTabs = $$('.cam__mode-tab');
  const scanBtn  = $('#scan-btn');
  const clearBtn = $('#clear-btn');
  const exportCsv = $('#export-csv');
  const exportJson = $('#export-json');
  const deviceCount = $('#device-count');
  const deviceCountNum = deviceCount ? deviceCount.querySelector('.cam__device-count__num') : null;
  const scanStatus = $('#scan-status');
  const statusIcon = scanStatus ? scanStatus.querySelector('.cam__status-dot__icon') : null;
  const statusLabel = scanStatus ? scanStatus.querySelector('.cam__status-dot__label') : null;
  const progressBar = $('#progress-bar');
  const progressFill = $('#progress-fill');
  const progressText = $('#progress-text');
  const searchInput = $('#search-input');
  const tableBody = $('#device-tbody');
  const detailPanel = $('#detail-panel');
  const detailTitle = $('#detail-title');
  const detailBody = $('#detail-body');
  const detailClose = $('#detail-close');
  const sidebarEl = $('#sidebar');
  const sidebarCollapse = $('#sidebar-collapse');
  const confidenceFilter = $('#confidence-filter');
  const confidenceVal = $('#confidence-val');
  const vendorFilters = $('#vendor-filters');
  const typeFilters = $('#type-filters');
  const protocolFilters = $$('#protocol-filters input[type="checkbox"]');
  const subnetFilters = $('#subnet-filters');
  const tickerInner = $('#ticker-inner');
  const scanTime = $('#scan-time');
  const expandAllBtn = $('#btn-expand-all');
  const collapseAllBtn = $('#btn-collapse-all');
  const capturePosEl = $('#capture-pos');
  const capturePosIcon = $('#capture-pos-icon');
  const capturePosLabel = $('#capture-pos-label');
  const addSubnetBtn = $('#add-subnet-btn');
  const watchBtn = $('#watch-btn');

  // ─── Init ───────────────────────────────────────────────────────────
  async function init() {
    detectElectron();
    await loadInterfaces();
    await loadSites();
    await loadCurrentSite();
    await loadCapturePosition();
    await loadSubnetZones();
    bindEvents();
    connectSSE();
    await loadExistingDevices();
    await loadPersistedInventory();
    syncDisplayedDevices();
    purgeSweepSubnetStorage();
    initBottomTray();
    initSensorBanner();
    await refreshInterfaceProfile();
    setInterval(refreshInterfaceProfile, 15000);
    startScanStatusPolling();
  }

  // Poll scan status as a backstop so a missed SSE event cannot leave the
  // UI stuck in "Scanning" forever.
  function startScanStatusPolling() {
    if (scanStatusIntervalId) clearInterval(scanStatusIntervalId);
    scanStatusIntervalId = setInterval(pollScanStatus, 3000);
  }

  async function pollScanStatus() {
    try {
      const resp = await apiFetch('/api/status');
      if (!resp.ok) return;
      const status = await resp.json();
      if (!status.scanning && isScanning) {
        // Backend scan finished without us seeing the SSE event.
        setScanning(false);
        await loadExistingDevices();
        scheduleRender();
      }
    } catch(_) {}
  }

  function purgeSweepSubnetStorage() {
    // The sweep-subnets field is intentionally NOT persisted. Wipe any value
    // a previous build may have stored so it can never silently re-inject
    // stale targets (e.g. a 172.16.1-22.0/24 range) into future scans.
    try { localStorage.removeItem('cam_sweep_subnets'); } catch(_) {}
  }

  // ─── Bottom tray (Triage + Lost/Mismatched) ─────────────────────────
  // Replaces the two floating bottom panels with a single layout-owned tray
  // that collapses to a thin bar and never overlays the device table.

  let trayExpanded = false;
  let trayActiveTab = 'triage';
  let triageIntervalId = null;
  let lostIntervalId = null;
  let scanStatusIntervalId = null;

  function initBottomTray() {
    const tray = document.getElementById('bottom-tray');
    const header = document.getElementById('bottom-tray-header');
    if (!tray || !header) return;

    header.addEventListener('click', (e) => {
      const tabBtn = e.target.closest('[data-tray-tab]');
      if (tabBtn) {
        setTrayTab(tabBtn.dataset.trayTab);
        if (!trayExpanded) setTrayExpanded(true);
        return;
      }
      const toggle = e.target.closest('#tray-toggle');
      if (toggle) {
        setTrayExpanded(!trayExpanded);
        return;
      }
      const refresh = e.target.closest('#tray-refresh');
      if (refresh) {
        refreshTriage();
        refreshLostDevices();
        return;
      }
      const ingest = e.target.closest('#tray-ingest');
      if (ingest) {
        openIngestModal();
      }
    });

    // Slow polling when collapsed, normal when expanded.
    scheduleTrayPolling();
    refreshTriage();
    refreshLostDevices();
  }

  function setTrayTab(tab) {
    trayActiveTab = tab;
    const tray = document.getElementById('bottom-tray');
    tray.querySelectorAll('[data-tray-tab]').forEach(b =>
      b.classList.toggle('cam__tray__tab--active', b.dataset.trayTab === tab));
    tray.querySelectorAll('.cam__tray__panel').forEach(p =>
      p.classList.toggle('cam__tray__panel--active', p.id === `tray-panel-${tab}`));
  }

  function setTrayExpanded(expanded) {
    trayExpanded = expanded;
    const tray = document.getElementById('bottom-tray');
    tray.classList.toggle('cam__tray--collapsed', !expanded);
    scheduleTrayPolling();
  }

  function scheduleTrayPolling() {
    if (triageIntervalId) clearInterval(triageIntervalId);
    if (lostIntervalId) clearInterval(lostIntervalId);
    const triageMs = trayExpanded ? 3000 : 12000;
    const lostMs   = trayExpanded ? 6000 : 18000;
    triageIntervalId = setInterval(refreshTriage, triageMs);
    lostIntervalId   = setInterval(refreshLostDevices, lostMs);
  }



  async function refreshTriage() {
    let s;
    try {
      const r = await apiFetch('/api/triage');
      if (!r.ok) return;
      s = await r.json();
    } catch(_) { return; }

    const body = document.getElementById('tray-panel-triage');
    if (!body) return;

    const rows = (arr, fmt) => arr.length
      ? arr.map(fmt).join('')
      : '<div class="cam__tray__empty">none</div>';

    const scope = (s.known_scopes || []).map(k =>
      `<div class="cam__tray__row"><span>${esc(k.cidr)} <em>(${esc(k.source)})</em></span>` +
      `<span>${k.completed ? 'done' : (k.next_host + '/254')}</span></div>`).join('')
      || '<div class="cam__tray__empty">none</div>';

    const mm = rows((s.mismatch || []).slice(0, 12), m =>
      `<div class="cam__tray__row"><span>${esc(m.ip)}</span>` +
      `<span title="${esc(m.reason)}">${esc(m.status)}</span></div>`);

    const cand = rows((s.candidates || []).slice(0, 12), c =>
      `<div class="cam__tray__row"><span>${esc(c.cidr)} ${c.confidence}%</span>` +
      `<span>${esc(c.status)}</span></div>`);

    const orph = rows((s.orphans || []).slice(0, 10), o =>
      `<div class="cam__tray__row"><span>${esc(o.ip || o.mac)}</span>` +
      `<span>${esc(o.status)}</span></div>`);

    const gwmm = rows((s.gateway_mismatch || []).slice(0, 6), g =>
      `<div class="cam__tray__row"><span>${esc(g.ip)}</span>` +
      `<span title="${esc(g.reason)}" style="color:#d29922">&#8594; ${esc(g.observed_target_gateway || '?')}</span></div>`);

    const mcast = rows((s.multicast_groups || []).slice(0, 6), g =>
      `<div class="cam__tray__row"><span>${esc(g.group)}</span>` +
      `<span style="color:#8b949e">${esc(g.protocol_hint)} &#183; ${g.packet_count}pkt</span></div>`);

    const p5 = rows((s.camera_validation || []).slice(0, 8), v => {
      const statusColour = v.status === 'pass' ? '#7ee787'
        : v.status === 'fail' ? '#f85149'
        : v.status === 'validating' ? '#d29922' : '#8b949e';
      const checks = [
        v.onvif_ok ? 'ONVIF' : null,
        v.rtsp_ok  ? 'RTSP'  : null,
        v.http_ok  ? 'HTTP'  : null,
        v.nvr_match? 'NVR'   : null,
      ].filter(Boolean).join(' ');
      return `<div class="cam__tray__row"><span>${esc(v.ip)}</span>` +
        `<span style="color:${statusColour}">${esc(v.status)}${checks ? ' ' + checks : ''}</span></div>`;
    });

    body.innerHTML =
      `<div class="cam__tray__task">${esc(s.current_task || 'Idle.')}</div>` +
      `<div class="cam__tray__sec">P1 Known scopes</div>${scope}` +
      `<div class="cam__tray__sec">P2 Mismatch (one at a time)</div>${mm}` +
      `<div class="cam__tray__sec">Gateway mismatch (old static config)</div>${gwmm}` +
      `<div class="cam__tray__sec">P3 Lost / candidate networks</div>${cand}` +
      `<div class="cam__tray__sec">P4 Orphans</div>${orph}` +
      `<div class="cam__tray__sec">P5 Camera validation (Arm 7)</div>${p5}` +
      `<div class="cam__tray__sec">Multicast groups (monitor only)</div>${mcast}`;

    const badge = document.getElementById('tray-badge-triage');
    if (badge) {
      const total = (s.mismatch || []).length + (s.gateway_mismatch || []).length +
                    (s.orphans || []).length + (s.candidates || []).length +
                    (s.camera_validation || []).length;
      badge.textContent = total;
      badge.style.display = total ? '' : 'none';
    }
  }

  // ─── Sensor quality banner ──────────────────────────────────────────
  // Shows adapter position quality (Wi-Fi=limited, mirror=full) above the table.

  function initSensorBanner() {
    const style = document.createElement('style');
    style.textContent = `
      #sensor-banner{padding:5px 12px;font:11px ui-monospace,monospace;
        display:flex;align-items:center;gap:10px;flex-wrap:wrap;
        border-bottom:1px solid #21262d;margin-bottom:4px}
      #sensor-banner.ok{background:#0d2a1a;color:#7ee787}
      #sensor-banner.warn{background:#2b1a00;color:#d29922}
      #sensor-banner.hidden{display:none}
      #sensor-banner .sb-badge{font-weight:bold;font-size:10px;
        padding:1px 6px;border-radius:3px;background:#1a3f00}
      #sensor-banner.warn .sb-badge{background:#4a2c00}
      #sensor-banner .sb-warnings{font-size:10px;color:#f0883e;margin-left:auto}
      #iface-warning{background:#1a1000;border:1px solid #d29922;border-radius:4px;
        padding:4px 10px;font:11px ui-monospace,monospace;color:#d29922;
        margin:4px 0;display:none}`;
    document.head.appendChild(style);

    const banner = document.createElement('div');
    banner.id = 'sensor-banner';
    banner.className = 'hidden';
    const tableWrap = $('#device-tbody');
    const parent = tableWrap ? tableWrap.closest('table') || tableWrap.parentElement : null;
    if (parent && parent.parentElement) {
      parent.parentElement.insertBefore(banner, parent);
    }

    const warn = document.createElement('div');
    warn.id = 'iface-warning';
    if (parent && parent.parentElement) {
      parent.parentElement.insertBefore(warn, parent);
    }
  }

  async function refreshInterfaceProfile() {
    try {
      const r = await apiFetch('/api/interface-profile');
      if (!r.ok) return;
      const p = await r.json();

      // Sensor banner
      const banner = document.getElementById('sensor-banner');
      if (banner && p.sensor) {
        const s = p.sensor;
        const cls = s.colour === 'ok' ? 'ok' : 'warn';
        banner.className = cls;
        banner.innerHTML =
          `<span class="sb-badge">Sensor: ${esc(s.quality)}</span>` +
          `<span>${esc(s.label)}</span>` +
          `<span>${esc(s.note)}</span>` +
          (p.temp_ips && p.temp_ips.length
            ? `<span class="sb-warnings">&#9888; Temp IPs: ${p.temp_ips.join(', ')}</span>` : '');
      }

      // Interface warnings
      const warnEl = document.getElementById('iface-warning');
      if (warnEl) {
        if (p.warnings && p.warnings.length) {
          warnEl.style.display = '';
          warnEl.innerHTML = p.warnings.map(w => `&#9888; ${esc(w)}`).join('<br>');
        } else {
          warnEl.style.display = 'none';
        }
      }
    } catch(_) {}
  }


  async function refreshLostDevices() {
    try {
      const r = await apiFetch('/api/lost-devices');
      if (!r.ok) return;
      const data = await r.json();

      const total = data.total || 0;
      const body = document.getElementById('tray-panel-lost');
      const badge = document.getElementById('tray-badge-lost');
      if (badge) {
        badge.textContent = total;
        badge.style.display = total ? '' : 'none';
      }
      if (!body) return;
      if (total === 0) {
        body.innerHTML = '<div class="cam__tray__empty">No lost devices detected.</div>';
        return;
      }

      let html = '';

      // Gateway mismatches — most urgent
      if (data.gateway_mismatches && data.gateway_mismatches.length) {
        html += '<div class="cam__tray__sec">Gateway mismatch (old static config)</div>';
        for (const g of data.gateway_mismatches.slice(0, 8)) {
          html +=
            `<div class="cam__tray__row cam__tray__row--lost">` +
            `<span class="ip">${esc(g.ip)}</span>` +
            `<span class="badge gw">GW MISMATCH</span>` +
            (g.warn_reset ? `<span class="warn-reset"> &#9888; do not reset</span>` : '') +
            `<div class="detail">` +
            (g.vendor ? esc(g.vendor) + ' &bull; ' : '') +
            `Targeting: <strong>${esc(g.observed_target_gateway || '?')}</strong>` +
            (g.suspected_old_subnet ? ` &rarr; ${esc(g.suspected_old_subnet)}` : '') +
            `</div>` +
            `<div class="detail">${esc(g.reason || '')}</div>` +
            (g.next_action ? `<div class="next">&#8594; ${esc(g.next_action)}</div>` : '') +
            `</div>`;
        }
      }

      // Subnet mismatches
      if (data.mismatches && data.mismatches.length) {
        html += '<div class="cam__tray__sec">Subnet mismatch (one at a time)</div>';
        for (const m of data.mismatches.slice(0, 8)) {
          html +=
            `<div class="cam__tray__row cam__tray__row--lost">` +
            `<span class="ip">${esc(m.ip)}</span>` +
            `<span class="badge">${esc(m.status || 'observed')}</span>` +
            (m.warn_reset ? `<span class="warn-reset"> &#9888; do not reset</span>` : '') +
            `<div class="detail">` +
            (m.vendor ? esc(m.vendor) + ' &bull; ' : '') +
            esc(m.reason || '') +
            `</div>` +
            `</div>`;
        }
      }

      // Orphans
      if (data.orphans && data.orphans.length) {
        html += '<div class="cam__tray__sec">Orphans (switch/NVR/DHCP/passive only)</div>';
        for (const o of data.orphans.slice(0, 10)) {
          const label = o.ip || o.mac || 'unknown';
          html +=
            `<div class="cam__tray__row cam__tray__row--lost">` +
            `<span class="ip">${esc(label)}</span>` +
            `<span class="badge orphan">${esc(o.status || 'orphan')}</span>` +
            `<div class="detail">${esc(o.reason || '')}</div>` +
            (o.camera_confidence > 0
              ? `<div class="next">Camera confidence: ${o.camera_confidence}%</div>` : '') +
            `</div>`;
        }
      }

      body.innerHTML = html || '<div class="cam__tray__empty">No lost devices detected.</div>';
    } catch(_) {}
  }

  function detectElectron() {
    const isElectron = !!(window.electronAPI && window.electronAPI.isElectron);
    if (isElectron) {
      document.body.classList.add('is-electron');

      // Wire up title bar controls
      const btnMin = document.getElementById('btn-minimize');
      const btnMax = document.getElementById('btn-maximize');
      const btnClose = document.getElementById('btn-close');

      if (btnMin) btnMin.addEventListener('click', () => window.electronAPI.minimize());
      if (btnMax) btnMax.addEventListener('click', () => window.electronAPI.maximize());
      if (btnClose) btnClose.addEventListener('click', () => window.electronAPI.close());
    }
  }

  async function loadInterfaces() {
    try {
      const resp = await apiFetch('/api/interfaces');
      const ifaces = await resp.json();
      if (!Array.isArray(ifaces)) throw new Error('Invalid interfaces response');
      ifaceSelect.innerHTML = '<option value="">Auto-detect</option>';
      ifaces.forEach(i => {
        const opt = document.createElement('option');
        opt.value = i.name;
        opt.textContent = `${i.name} (${i.ip}) — ${i.iface_type}`;
        if (i.iface_type === 'ethernet') opt.selected = true;
        ifaceSelect.appendChild(opt);
      });
    } catch(e) {
      console.error('Failed to load interfaces:', e);
    }
  }

  async function loadExistingDevices() {
    try {
      const resp = await apiFetch('/api/devices');
      const data = await resp.json();
      if (!Array.isArray(data)) throw new Error('Invalid devices response');
      liveDevices = data;
      syncDisplayedDevices();
    } catch(e) { /* no existing devices */ }
  }

  async function loadSites() {
    try {
      const resp = await apiFetch('/api/sites');
      const data = await resp.json();
      if (!Array.isArray(data)) throw new Error('Invalid sites response');
      sites = data;
      renderSiteOptions();
    } catch(e) { /* ignore */ }
  }

  async function loadCurrentSite() {
    try {
      const resp = await apiFetch('/api/sites/current');
      const data = await resp.json();
      currentSiteId = data.site_id || '';
      renderSiteOptions();
      renderInventoryMode();
    } catch(e) { /* ignore */ }
  }

  async function setCurrentSite(siteId) {
    const resp = await apiFetch('/api/sites/current', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ site_id: siteId || null }),
    });
    const data = await resp.json();
    if (!resp.ok) {
      throw new Error(data.error || 'Failed to set site');
    }
    currentSiteId = data.site_id || '';
    renderSiteOptions();
    await loadPersistedInventory();
    syncDisplayedDevices();
  }

  async function loadPersistedInventory() {
    if (!currentSiteId) {
      persistedInventory = [];
      if (inventoryMode === 'persisted') syncDisplayedDevices();
      return;
    }
    try {
      const resp = await apiFetch(`/api/inventory/current?site_id=${encodeURIComponent(currentSiteId)}`);
      const data = await resp.json();
      if (!Array.isArray(data)) throw new Error('Invalid inventory response');
      persistedInventory = data;
      if (inventoryMode === 'persisted') syncDisplayedDevices();
    } catch(e) { /* ignore */ }
  }

  function renderSiteOptions() {
    if (!siteSelect) return;
    siteSelect.innerHTML = '<option value="">No Site Bound</option>';
    sites.forEach(site => {
      const opt = document.createElement('option');
      opt.value = site.site_id;
      opt.textContent = site.name;
      if (site.site_id === currentSiteId) opt.selected = true;
      siteSelect.appendChild(opt);
    });
  }

  function mapPersistedInventoryRow(row) {
    const endpoint = row.endpoint || {};
    const asset = row.asset || {};
    const observations = row.observations || [];
    const vendor = asset.manufacturer || 'Unknown';
    const model = asset.model || '';
    const freshness = row.freshness || { state: 'unknown', as_of: endpoint.last_seen || null };
    const openPorts = [];
    const protocols = new Set();
    const addPort = (value) => {
      const port = Number(value);
      if (port > 0 && !openPorts.includes(port)) openPorts.push(port);
    };
    const addUrlPort = (rawUrl, fallback) => {
      if (!rawUrl) return;
      try {
        const parsed = new URL(rawUrl);
        addPort(parsed.port || fallback);
      } catch (_) {
        addPort(fallback);
      }
    };
    const hostnameObs = observations.find(o => o.kind === 'dns_name_seen');
    const hostname = hostnameObs && hostnameObs.detail
      ? String(hostnameObs.detail).replace(/^DNS name observed:\s*/i, '')
      : '';
    if (endpoint.web_url) {
      protocols.add('HTTP');
      addUrlPort(endpoint.web_url, endpoint.web_url.startsWith('https://') ? 443 : 80);
    }
    if (endpoint.rtsp_url) {
      protocols.add('RTSP');
      addUrlPort(endpoint.rtsp_url, 554);
    }
    if (endpoint.onvif_url) {
      protocols.add('ONVIF');
      addUrlPort(endpoint.onvif_url, 80);
    }
    observations.forEach(o => {
      if (o.kind === 'wsd_onvif_probe_match' || o.kind === 'onvif_device_service_seen') protocols.add('ONVIF');
      if (o.kind === 'rtsp_describe_seen' || o.kind === 'rtsp_session_seen') protocols.add('RTSP');
      if (o.kind === 'http_camera_marker_seen' || o.kind === 'http_endpoint_seen') protocols.add('HTTP');
    });
    const weightedEvidence = observations.reduce((sum, obs) => sum + (Number(obs.weight) || 0), 0);
    const persistedConfidence = Math.max(
      15,
      Math.min(
        95,
        (asset.asset_class === 'camera' ? 35 : 20) +
        (endpoint.device_class === 'camera' ? 20 : 0) +
        (asset.serial ? 8 : 0) +
        (asset.onvif_uuid ? 10 : 0) +
        Math.max(weightedEvidence, 0)
      )
    );
    return {
      device_id: asset.asset_id || endpoint.endpoint_id || endpoint.ip || '',
      asset_id: asset.asset_id || '',
      endpoint_id: endpoint.endpoint_id || '',
      ip: endpoint.ip || '',
      ip_history: endpoint.ip_history || [],
      mac: endpoint.mac || '',
      mac_history: endpoint.mac_history || [],
      serial: asset.serial || '',
      onvif_uuid: asset.onvif_uuid || endpoint.onvif_uuid || '',
      vendor,
      hostname,
      model,
      firmware: endpoint.firmware || '',
      open_ports: openPorts.sort((a, b) => a - b),
      protocols: Array.from(protocols),
      onvif_status: endpoint.onvif_url ? 'found' : 'not-checked',
      rtsp_status: endpoint.rtsp_url ? 'found' : 'not-checked',
      web_url: endpoint.web_url || '',
      rtsp_url: endpoint.rtsp_url || '',
      onvif_url: endpoint.onvif_url || '',
      subnet: endpoint.subnet || '',
      confidence: persistedConfidence,
      fingerprint_score: persistedConfidence,
      discovery_methods: observations.map(o => o.source).filter(Boolean),
      last_seen: endpoint.last_seen || '',
      evidence: observations.map(o => ({
        kind: o.kind,
        detail: o.detail,
        source: o.source,
        weight: o.weight,
        timestamp: o.observed_at,
      })),
      subnet_mismatch: '',
      dpi_stages: {},
      dpi_score: null,
      dpi_summary: 'Derived from persisted evidence',
      subnet_zone: '',
      device_class: endpoint.device_class || 'unknown',
      device_type: asset.asset_class === 'workstation' ? 'computer' : (endpoint.device_class || 'unknown'),
      asset_class: asset.asset_class || '',
      device_type_confidence: 55,
      warn_reset: false,
      suspected_old_gateway: '',
      poe_state: '',
      notes: asset.notes || '',
      apipa_seen: false,
      validation: {},
      classification_rationale: 'Persisted inventory record with reconciled endpoint evidence',
      persisted: true,
      installed_status: asset.installed_status || '',
      expected_location_id: asset.expected_location_id || '',
      observation_count: observations.length,
      freshness_state: freshness.state || 'unknown',
      stale: freshness.state === 'stale',
      freshness_as_of: freshness.as_of || endpoint.last_seen || '',
    };
  }

  function syncDisplayedDevices() {
    devices = inventoryMode === 'persisted'
      ? persistedInventory.map(mapPersistedInventoryRow)
      : [...liveDevices];
    renderInventoryMode();
    renderTable();
    updateStats();
  }

  // Coalesce rapid device updates (SSE bursts during a sweep) into one render
  // every 250 ms so the DOM does not get repainted dozens of times/sec.
  let _renderPending = false;
  let _renderTimer = null;
  function scheduleRender() {
    if (_renderPending) return;
    _renderPending = true;
    if (_renderTimer) clearTimeout(_renderTimer);
    _renderTimer = setTimeout(() => {
      _renderPending = false;
      _renderTimer = null;
      syncDisplayedDevices();
    }, 250);
  }

  function renderInventoryMode() {
    if (!inventoryToggle) return;
    inventoryToggle.textContent = inventoryMode === 'persisted' ? 'Persisted View' : 'Live View';
    inventoryToggle.classList.toggle('cam__export-btn--active', inventoryMode === 'persisted');
  }

  async function loadCapturePosition() {
    try {
      const resp = await apiFetch('/api/capture-position');
      capturePosition = await resp.json();
      renderCapturePosition();
    } catch(e) { /* ignore */ }
  }

  async function loadSubnetZones() {
    try {
      const resp = await apiFetch('/api/subnets');
      const data = await resp.json();
      if (!Array.isArray(data)) throw new Error('Invalid subnet response');
      subnetZones = data;
      renderSubnetZones();
    } catch(e) { /* ignore */ }
  }

  // ─── SSE ────────────────────────────────────────────────────────────
  // SSE reconnect control — avoid tight reconnect loops that make the UI flash.
  let _sseReconnectDelay = 1000;
  let _sseFailures = 0;
  const _sseMaxDelay = 30000;
  const _sseMaxFailures = 20;
  let _sseReconnectTimer = null;

  async function connectSSE() {
    if (eventSource) {
      eventSource.close();
      eventSource = null;
    }
    if (_sseFailures >= _sseMaxFailures) {
      addActivityEvent('error', 'Live updates disconnected — too many retry failures');
      return;
    }

    let eventsUrl = '/api/events';
    if (window.electronAPI && window.electronAPI.getBackendSecrets) {
      const secrets = await window.electronAPI.getBackendSecrets();
      const url = new URL('/api/events', secrets.url);
      url.searchParams.set('backend_token', secrets.token || '');
      eventsUrl = url.toString();
    }

    const es = new EventSource(eventsUrl);
    eventSource = es;

    es.addEventListener('open', () => {
      _sseFailures = 0;
      _sseReconnectDelay = 1000;
    });

    es.addEventListener('message', (e) => {
      try {
        const msg = JSON.parse(e.data);
        handleEvent(msg);
      } catch(err) { /* heartbeat or parse error */ }
    });

    es.onerror = () => {
      es.close();
      _sseFailures++;
      const delay = Math.min(_sseReconnectDelay * 2, _sseMaxDelay);
      _sseReconnectDelay = delay;
      if (_sseReconnectTimer) clearTimeout(_sseReconnectTimer);
      _sseReconnectTimer = setTimeout(connectSSE, delay);
    };
  }

  function handleEvent(msg) {
    const { type, data } = msg;

    switch(type) {
      case 'device_found':
        upsertDevice(data);
        addActivityEvent('found', `Found ${data.ip} — ${data.vendor}`);
        scheduleRender();
        if (inventoryMode === 'persisted' && currentSiteId) loadPersistedInventory();
        break;

      case 'device_updated':
        upsertDevice(data);
        scheduleRender();
        if (inventoryMode === 'persisted' && currentSiteId) loadPersistedInventory();
        break;

      case 'progress':
        updateProgress(data);
        break;

      case 'scan_complete':
        setScanning(false);
        addActivityEvent('found', `Scan complete — ${data.device_count} devices found`);
        break;

      case 'subnet_sniffed':
        handleSubnetSniffed(data);
        break;

      case 'subnet_added':
        loadSubnetZones();
        break;

      case 'subnet_removed':
        loadSubnetZones();
        break;

      case 'capture_position_changed':
        capturePosition = data;
        renderCapturePosition();
        break;

      case 'devices_cleared':
        liveDevices = [];
        scheduleRender();
        addActivityEvent('found', 'Device list cleared');
        break;

      case 'error':
        addActivityEvent('error', data.message);
        break;
    }
  }

  // ─── Scan control ───────────────────────────────────────────────────
  function bindEvents() {
    // Mode tabs
    modeTabs.forEach(tab => {
      on(tab, 'click', () => {
        modeTabs.forEach(t => t.classList.remove('cam__mode-tab--active'));
        tab.classList.add('cam__mode-tab--active');
        currentMode = tab.dataset.mode;
        if (app) app.dataset.mode = currentMode;
      });
    });

    // Scan button
    on(scanBtn, 'click', () => {
      if (isScanning) stopScan();
      else startScan();
    });

    // Clear button — wipes device list (only works when not scanning)
    on(clearBtn, 'click', async () => {
      if (isScanning) {
        addActivityEvent('error', 'Stop the scan before clearing results');
        return;
      }
      if (!confirm('Clear all discovered devices?')) return;
      try {
        const resp = await apiFetch('/api/devices/clear', { method: 'POST' });
        if (!resp.ok) {
          const err = await resp.json();
          addActivityEvent('error', err.error || 'Clear failed');
        }
      } catch(e) {
        addActivityEvent('error', 'Failed to clear devices');
      }
    });

    // Export
    on(exportCsv, 'click', () => downloadExport('/api/export/csv', 'network-discovery.csv'));
    on(exportJson, 'click', () => downloadExport('/api/export/json', 'network-discovery.json'));
    const exportHtml = $('#export-html');
    if (exportHtml) {
      on(exportHtml, 'click', () => downloadExport('/api/export/html', 'network-discovery.html'));
    }

    // Search
    on(searchInput, 'input', debounce(renderTable, 200));

    on(siteSelect, 'change', async () => {
      try {
        await setCurrentSite(siteSelect.value);
        addActivityEvent('found', currentSiteId ? `Bound session to site` : 'Cleared site binding');
      } catch (e) {
        addActivityEvent('error', e.message || 'Failed to bind site');
      }
    });

    on(inventoryToggle, 'click', async () => {
      if (inventoryMode === 'live') {
        if (!currentSiteId) {
          addActivityEvent('error', 'Bind a site before using persisted inventory');
          return;
        }
        await loadPersistedInventory();
        inventoryMode = 'persisted';
      } else {
        inventoryMode = 'live';
      }
      syncDisplayedDevices();
    });

    // Sidebar collapse
    on(sidebarCollapse, 'click', () => {
      if (!sidebarEl || !sidebarCollapse) return;
      sidebarEl.classList.toggle('cam__sidebar--collapsed');
      const isCollapsed = sidebarEl.classList.contains('cam__sidebar--collapsed');
      sidebarCollapse.textContent = isCollapsed ? '\u25B6' : '\u25C0';
    });

    // Confidence filter
    on(confidenceFilter, 'input', () => {
      if (confidenceVal && confidenceFilter) {
        confidenceVal.textContent = confidenceFilter.value + '%+';
      }
      renderTable();
    });

    // Protocol filters
    protocolFilters.forEach(cb => on(cb, 'change', renderTable));

    // Sort
    $$('.cam__th[data-sort]').forEach(th => {
      on(th, 'click', () => {
        const field = th.dataset.sort;
        if (sortField === field) {
          sortDir = sortDir === 'asc' ? 'desc' : 'asc';
        } else {
          sortField = field;
          sortDir = 'asc';
        }
        renderTable();
      });
    });

    // Detail panel close
    on(detailClose, 'click', closeDetail);
    on(document, 'keydown', (e) => {
      if (e.key === 'Escape') {
        closeDetail();
        closeAnyDialog();
      }
    });

    // Expand/collapse all
    on(expandAllBtn, 'click', () => {
      $$('.cam__expand-btn').forEach(b => b.classList.add('cam__expand-btn--open'));
      $$('.cam__detail-row').forEach(r => r.style.display = '');
    });
    on(collapseAllBtn, 'click', () => {
      $$('.cam__expand-btn').forEach(b => b.classList.remove('cam__expand-btn--open'));
      $$('.cam__detail-row').forEach(r => r.style.display = 'none');
    });

    // Capture position click
    on(capturePosEl, 'click', showCapturePositionDialog);

    // Add subnet button
    on(addSubnetBtn, 'click', showAddSubnetDialog);

    // Subnet watch toggle
    on(watchBtn, 'click', toggleWatch);
  }

  async function toggleWatch() {
    if (isWatching) {
      await apiFetch('/api/subnet-watch/stop', { method: 'POST' });
      isWatching = false;
      watchBtn.classList.remove('cam__watch-btn--active');
      addActivityEvent('warn', 'Subnet watch stopped');
    } else {
      await apiFetch('/api/subnet-watch/start', { method: 'POST' });
      isWatching = true;
      watchBtn.classList.add('cam__watch-btn--active');
      addActivityEvent('found', 'Subnet watch started — sniffing for new subnets...');
    }
  }

  function handleSubnetSniffed(data) {
    const { subnet, first_seen_ip, source } = data;
    if (!sniffedSubnets.includes(subnet)) {
      sniffedSubnets.push(subnet);
    }
    addActivityEvent('found',
      `Subnet sniffed: ${subnet} (${source}, first host ${first_seen_ip}) — auto-scanning`);
    // Refresh subnet zones after a short delay to pick up the auto-added zone
    setTimeout(loadSubnetZones, 1500);
    // Flash a visual badge on the subnet section
    const subnetSection = $('#subnet-filters');
    if (subnetSection) {
      subnetSection.closest('.cam__sidebar-section').classList.add('cam__sidebar-section--flash');
      setTimeout(() => {
        subnetSection.closest('.cam__sidebar-section').classList.remove('cam__sidebar-section--flash');
      }, 2000);
    }
  }

  async function startScan() {
    setScanning(true);
    // Do NOT clear devices — preserve previously found cameras across mode switches.
    // Use the explicit Clear button to reset.

    // Collect sweep subnets (if any) from the sweep bar input
    let subnets = null;
    if (currentMode === 'sweep') {
      const sweepInput = document.getElementById('sweep-subnets');
      const raw = sweepInput ? sweepInput.value.trim() : '';
      if (raw) {
        // Split on commas so user can enter multiple ranges/subnets.
        // Use exactly what is in the box right now — nothing is persisted
        // or restored, so a scan only ever targets what the operator
        // explicitly typed for THIS scan.
        subnets = raw.split(',').map(s => s.trim()).filter(Boolean);
        addActivityEvent('found', `Sweep targets: ${subnets.join(', ')}`);
      } else {
        addActivityEvent('found', 'Sweep: auto-detecting subnets + built-in camera list');
      }
    }

    try {
      const resp = await apiFetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mode: currentMode,
          interface: ifaceSelect.value,
          subnets,       // null = auto-detect; array = explicit targets
          clear: false,  // preserve evidence across mode switches; use Clear button to reset
        }),
      });
      if (!resp.ok) {
        const err = await resp.json();
        addActivityEvent('error', err.error || 'Scan failed');
        setScanning(false);
      }
    } catch(e) {
      addActivityEvent('error', e.message || 'Network error starting scan');
      // A 409 "already running" or transient network hiccup should not flip
      // the spinner off if the backend is still scanning. Poll status to sync.
      pollScanStatus().catch(() => setScanning(false));
    }
  }

  // Upsert helper — both device_found and device_updated go through here so
  // the table never contains duplicate rows regardless of event ordering.
  function upsertDevice(d) {
    const idx = liveDevices.findIndex(x =>
      (d.endpoint_id && x.endpoint_id && x.endpoint_id === d.endpoint_id) ||
      (d.asset_id && x.asset_id && x.asset_id === d.asset_id) ||
      x.ip === d.ip
    );
    if (idx >= 0) liveDevices[idx] = d;
    else liveDevices.push(d);
  }

  async function stopScan() {
    try {
      await apiFetch('/api/scan/stop', { method: 'POST' });
      setScanning(false);
    } catch(e) { /* ignore */ }
  }

  function setScanning(state) {
    isScanning = state;
    if (state) {
      if (scanBtn) {
        scanBtn.className = 'cam__scan-btn cam__scan-btn--stop';
        scanBtn.innerHTML = '<span class="cam__scan-btn__icon">\u25A0</span> Stop';
      }
      if (statusIcon) statusIcon.className = 'cam__status-dot__icon cam__status-dot__icon--active';
      if (statusLabel) statusLabel.textContent = 'Scanning';
      if (progressBar) progressBar.style.display = '';
      scanStartTime = Date.now();
      scanTimer = setInterval(updateScanTime, 1000);
    } else {
      if (scanBtn) {
        scanBtn.className = 'cam__scan-btn cam__scan-btn--start';
        scanBtn.innerHTML = '<span class="cam__scan-btn__icon">\u25B6</span> Start Scan';
      }
      if (statusIcon) statusIcon.className = 'cam__status-dot__icon cam__status-dot__icon--idle';
      if (statusLabel) statusLabel.textContent = 'Idle';
      if (progressBar) progressBar.style.display = 'none';
      if (scanTimer) { clearInterval(scanTimer); scanTimer = null; }
    }
  }

  function updateScanTime() {
    if (!scanStartTime) return;
    const elapsed = Math.floor((Date.now() - scanStartTime) / 1000);
    const mins = String(Math.floor(elapsed / 60)).padStart(2, '0');
    const secs = String(elapsed % 60).padStart(2, '0');
    if (scanTime) scanTime.textContent = `${mins}:${secs}`;
  }

  function updateProgress(data) {
    if (progressFill && data.total > 0) {
      const pct = Math.round((data.current / data.total) * 100);
      progressFill.style.width = pct + '%';
    }
    if (progressText) progressText.textContent = data.message || '';
  }

  // ─── Rendering ──────────────────────────────────────────────────────
  function renderTable() {
    const filtered = getFilteredDevices();
    const sorted = sortDevices(filtered);

    if (sorted.length === 0) {
      tableBody.innerHTML = `
        <tr class="cam__empty-row">
          <td colspan="11">
              <div class="cam__empty-state">
                <div class="cam__empty-icon">&#9673;</div>
              <div class="cam__empty-text">${devices.length === 0 ? (inventoryMode === 'persisted' ? 'No persisted devices for this site' : 'No devices discovered yet') : 'No devices match filters'}</div>
              <div class="cam__empty-hint">${devices.length === 0 ? (inventoryMode === 'persisted' ? 'Bind a site and reconcile devices into inventory' : 'Select an interface and start a scan') : 'Adjust sidebar filters'}</div>
            </div>
          </td>
        </tr>`;
      return;
    }

    let html = '';
    sorted.forEach(device => {
      const isSelected = device.ip === selectedDeviceIp;
      const vendorClass = getVendorClass(device.vendor);
      const portTags = renderPortTags(device.open_ports);
      const onvifStatus = renderStatusIndicator(device.onvif_status);
      const rtspStatus = renderStatusIndicator(device.rtsp_status);
      const dpiBar = renderDPIBar(device.dpi_stages, device.dpi_score);
      const confidenceHtml = renderConfidence(device.confidence);
      const actionLinks = renderActionLinks(device);
      const persistedBadge = device.persisted
        ? `<span class="cam__record-badge" title="${device.stale ? 'Persisted record is older than 24 hours' : 'Site inventory record'}">${device.stale ? 'STALE' : 'REC'}</span>`
        : '';

      // Classification badges
      const displayType = displayDeviceType(device);
      const dcBadge = displayType !== 'unknown'
        ? `<span style="font-size:9px;padding:0 3px;border-radius:2px;background:#21262d;color:#8b949e;margin-left:3px">${esc(displayType.replace(/_/g, ' '))}</span>`
        : '';
      const warnBadge = device.warn_reset
        ? `<span style="font-size:9px;padding:0 3px;border-radius:2px;background:#4a1010;color:#f85149;margin-left:3px" title="Do not reset">&#9888; no-reset</span>`
        : '';
      const apipaBadge = device.apipa_seen
        ? `<span style="font-size:9px;padding:0 3px;border-radius:2px;background:#2b1a00;color:#d29922;margin-left:3px" title="${esc('APIPA \u2014 no DHCP/isolated segment')}">APIPA</span>`
        : '';
      const gwMismatchBadge = device.suspected_old_gateway
        ? `<span style="font-size:9px;padding:0 3px;border-radius:2px;background:#2b2000;color:#d29922;margin-left:3px" title="Old gateway: ${esc(device.suspected_old_gateway)}">GW?</span>`
        : '';

      html += `
        <tr class="cam__tr ${isSelected ? 'cam__tr--selected' : ''} ${device.persisted ? 'cam__tr--persisted' : 'cam__tr--new'}"
            data-ip="${esc(device.ip)}" onclick="window._selectDevice('${esc(device.ip)}')">
          <td class="cam__td">
            <button class="cam__expand-btn" onclick="event.stopPropagation(); window._toggleExpand('${esc(device.ip)}')">&#9654;</button>
          </td>
          <td class="cam__td cam__td--ip">${esc(device.ip)}${apipaBadge}${gwMismatchBadge}</td>
          <td class="cam__td cam__td--mac">${esc(device.mac || '\u2014')}</td>
          <td class="cam__td cam__td--vendor">
            <span class="cam__vendor-badge ${vendorClass}">${esc(device.vendor)}</span>${persistedBadge}${dcBadge}${warnBadge}
          </td>
          <td class="cam__td">${esc(device.model || '\u2014')}</td>
          <td class="cam__td cam__td--ports">${portTags}</td>
          <td class="cam__td">${onvifStatus}</td>
          <td class="cam__td">${rtspStatus}</td>
          <td class="cam__td">${dpiBar}</td>
          <td class="cam__td">${confidenceHtml}</td>
          <td class="cam__td">${actionLinks}</td>
        </tr>
        <tr class="cam__detail-row" data-detail-ip="${esc(device.ip)}" style="display:none;">
          <td colspan="11">
            <div class="cam__detail-expand">
              ${renderInlineDetail(device)}
            </div>
          </td>
        </tr>`;
    });

    tableBody.innerHTML = html;
    if (deviceCountNum) deviceCountNum.textContent = devices.length;
  }

  function renderInlineDetail(device) {
    const evidence = Array.isArray(device.evidence) ? device.evidence.slice().sort((a, b) => (b.weight || 0) - (a.weight || 0)) : [];
    const fields = [
      ['Record Source', device.persisted ? 'Persisted site inventory' : 'Live session'],
      ['IP Address', device.ip + (device.apipa_seen ? ' <span style="color:#d29922;font-size:10px">&#9888; APIPA</span>' : '')],
      ['MAC Address', device.mac || '\u2014'],
      ['Asset ID', device.asset_id || '\u2014'],
      ['Endpoint ID', device.endpoint_id || '\u2014'],
      ['Vendor', device.vendor],
      ['Device Type', displayDeviceType(device)],
      ...(device.asset_class ? [['Asset Class', device.asset_class]] : []),
      ...(device.freshness_state ? [['Freshness', `${device.freshness_state}${device.freshness_as_of ? ` — as of ${new Date(device.freshness_as_of).toLocaleString()}` : ''}`]] : []),
      ['Type Confidence', `${device.device_type_confidence != null ? device.device_type_confidence : 0}%`],
      ['Model', device.model || '\u2014'],
      ['Hostname', device.hostname || '\u2014'],
      ['Serial', device.serial || '\u2014'],
      ['ONVIF UUID', device.onvif_uuid || '\u2014'],
      ['Subnet', device.subnet || '\u2014'],
      ['Subnet Zone', device.subnet_zone || '\u2014'],
      ['ONVIF URL', device.onvif_url ? `<a href="${esc(device.onvif_url)}" target="_blank">${esc(device.onvif_url)}</a>` : '\u2014'],
      ['RTSP URL', device.rtsp_url ? `<a href="${esc(device.rtsp_url)}" target="_blank">${esc(device.rtsp_url)}</a>` : '\u2014'],
      ['Web URL', device.web_url ? `<a href="${esc(device.web_url)}" target="_blank">${esc(device.web_url)}</a>` : '\u2014'],
      ...(device.suspected_old_gateway ? [['Old Gateway', `<span style="color:#d29922">&#9888; ${esc(device.suspected_old_gateway)}</span> \u2014 likely old static config`]] : []),
      ...(device.warn_reset ? [['Warning', '<span style="color:#f85149;font-weight:bold">&#9888; Do not factory-reset without checking both ends</span>']] : []),
      ...(device.notes ? [['Notes', esc(device.notes)]] : []),
      ['Camera Confidence', device.confidence + '%'],
      ['Fingerprint Score', (device.fingerprint_score != null ? device.fingerprint_score + '%' : '\u2014')],
      ['DPI Score', (device.dpi_score != null ? device.dpi_score + '%' : '\u2014')],
      ['Discovery', (device.discovery_methods || []).join(', ')],
      ['PoE / Link State', device.poe_state || '\u2014'],
      ['Last Seen', device.last_seen ? new Date(device.last_seen).toLocaleTimeString() : '\u2014'],
      ...(device.persisted ? [['Persisted Observations', String(device.observation_count || 0)], ['Install State', device.installed_status || '\u2014']] : []),
    ];

    let html = '<div class="cam__detail-grid">';
    fields.forEach(([label, value]) => {
      const monoClass = /^(IP Address|MAC Address|Asset ID|Endpoint ID|Serial|ONVIF UUID|ONVIF URL|RTSP URL|Web URL|Last Seen)$/.test(label)
        ? ' cam__detail-field__value--mono'
        : '';
      html += `
        <div class="cam__detail-field">
          <span class="cam__detail-field__label">${label}</span>
          <span class="cam__detail-field__value${monoClass}">${value}</span>
        </div>`;
    });
    html += '</div>';

    // DPI stage detail grid
    if (device.dpi_stages && Object.keys(device.dpi_stages).length > 0) {
      html += '<div class="cam__dpi-stage-grid">';
      DPI_STAGES.forEach(stage => {
        const r = device.dpi_stages[stage];
        if (!r) return;
        html += `
          <div class="cam__dpi-stage-item">
            <span class="cam__dpi-stage-item__icon cam__dpi-stage-item__icon--${r.status}"></span>
            <span class="cam__dpi-stage-item__label">${DPI_LABELS[stage] || stage}</span>
            <span class="cam__dpi-stage-item__detail">${esc(r.detail || '')}</span>
          </div>`;
      });
      html += '</div>';
    }

    if (device.subnet_mismatch) {
      html += `
        <div class="cam__detail-alert">
          <span class="cam__detail-alert__label">Subnet mismatch</span>
          <span class="cam__detail-alert__text">${esc(device.subnet_mismatch)}</span>
        </div>`;
    }

    if (evidence.length > 0) {
      html += '<div class="cam__evidence-list">';
      evidence.forEach(ev => {
        const weightClass = (ev.weight || 0) > 0 ? 'cam__evidence-item__weight--pos' : ((ev.weight || 0) < 0 ? 'cam__evidence-item__weight--neg' : '');
        html += `
          <div class="cam__evidence-item">
            <span class="cam__evidence-item__weight ${weightClass}">${ev.weight > 0 ? '+' : ''}${ev.weight || 0}</span>
            <div class="cam__evidence-item__body">
              <div class="cam__evidence-item__detail">${esc(ev.detail || ev.kind || 'Evidence')}</div>
              <div class="cam__evidence-item__meta">${esc(ev.source || 'signal')}</div>
            </div>
          </div>`;
      });
      html += '</div>';
    }

    return html;
  }

  function renderPortTags(ports) {
    if (!ports || !ports.length) return '<span style="color:var(--text-label)">\u2014</span>';
    return ports.map(p => {
      let cls = 'other';
      if (p === 80 || p === 8080) cls = 'http';
      else if (p === 443) cls = 'https';
      else if (p === 554) cls = 'rtsp';
      else if (p === 3702 || p === 8899) cls = 'onvif';
      else if (p === 37777 || p === 37778) cls = 'dahua';
      else if (p === 8000) cls = 'hik';
      return `<span class="cam__port-tag cam__port-tag--${cls}">${p}</span>`;
    }).join('');
  }

  function renderStatusIndicator(status) {
    if (status === 'found') return '<span class="cam__status-indicator cam__status-indicator--found">&#10003;</span>';
    if (status === 'error') return '<span class="cam__status-indicator cam__status-indicator--error">&#10007;</span>';
    return '<span class="cam__status-indicator cam__status-indicator--unchecked">\u2014</span>';
  }

  function renderDPIBar(stages, score) {
    if (!stages || Object.keys(stages).length === 0) {
      return '<span style="color:var(--text-label);font-size:10px">\u2014</span>';
    }
    let html = '<div class="cam__dpi-bar">';
    DPI_STAGES.forEach(stage => {
      const s = stages[stage];
      if (!s) return;
      html += `<span class="cam__dpi-stage-dot cam__dpi-stage-dot--${s.status}" title="${DPI_LABELS[stage]}: ${s.detail}"></span>`;
    });
    if (score != null) {
      const cls = score >= 70 ? 'high' : score >= 40 ? 'medium' : 'low';
      html += `<span class="cam__dpi-score cam__dpi-score--${cls}">${score}%</span>`;
    }
    html += '</div>';
    return html;
  }

  function renderConfidence(score) {
    const cls = score >= 70 ? 'high' : score >= 40 ? 'medium' : 'low';
    return `
      <div class="cam__confidence-bar">
        <div class="cam__confidence-fill">
          <div class="cam__confidence-fill__inner cam__confidence-fill__inner--${cls}" style="width:${score}%"></div>
        </div>
        <span class="cam__confidence-val cam__confidence-val--${cls}">${score}%</span>
      </div>`;
  }

  function renderActionLinks(device) {
    let html = '<div class="cam__action-links">';
    const deviceType = displayDeviceType(device);
    const cameraish = ['camera', 'nvr'].includes(deviceType) || device.confidence >= 40;
    if (cameraish) {
      html += `<a class="cam__action-link cam__action-link--view" title="View camera" onclick="event.preventDefault(); event.stopPropagation(); window._viewCamera('${esc(device.ip)}')">&#128247;</a>`;
      html += `<a class="cam__action-link cam__action-link--setip" title="Change IP address" onclick="event.preventDefault(); event.stopPropagation(); window._showSetIPDialog('${esc(device.ip)}')">&#9998;</a>`;
    }
    if (device.web_url) {
      html += `<a class="cam__action-link cam__action-link--web" href="${esc(device.web_url)}" target="_blank" title="Open Web UI">&#127760;</a>`;
    }
    if (device.rtsp_url) {
      html += `<a class="cam__action-link cam__action-link--rtsp" href="${esc(device.rtsp_url)}" title="Copy RTSP URL" onclick="event.preventDefault(); event.stopPropagation(); navigator.clipboard.writeText('${esc(device.rtsp_url)}').then(()=>addActivityEvent('found','RTSP URL copied'))">&#9654;</a>`;
    }
    if (device.onvif_url) {
      html += `<a class="cam__action-link cam__action-link--onvif" href="${esc(device.onvif_url)}" target="_blank" title="ONVIF Endpoint">&#9881;</a>`;
    }
    html += `<a class="cam__action-link" style="background:rgba(34,211,238,.1);color:#22d3ee" title="Run DPI validation" onclick="event.preventDefault(); event.stopPropagation(); window._validateDPI('${esc(device.ip)}')">&#128065;</a>`;
    html += '</div>';
    return html;
  }

  function getVendorClass(vendor) {
    const v = (vendor || '').toLowerCase();
    if (v.includes('hikvision')) return 'cam__vendor-badge--hikvision';
    if (v.includes('dahua')) return 'cam__vendor-badge--dahua';
    if (v.includes('amcrest')) return 'cam__vendor-badge--amcrest';
    if (v.includes('axis')) return 'cam__vendor-badge--axis';
    if (v.includes('hanwha') || v.includes('wisenet')) return 'cam__vendor-badge--hanwha';
    if (v.includes('bosch')) return 'cam__vendor-badge--bosch';
    if (v.includes('reolink')) return 'cam__vendor-badge--reolink';
    if (v.includes('uniview')) return 'cam__vendor-badge--uniview';
    if (v.includes('vivotek')) return 'cam__vendor-badge--vivotek';
    if (v.includes('avigilon')) return 'cam__vendor-badge--avigilon';
    if (v.includes('lorex')) return 'cam__vendor-badge--lorex';
    if (v.includes('generic') || v.includes('onvif')) return 'cam__vendor-badge--generic';
    return 'cam__vendor-badge--unknown';
  }

  // ─── Filtering ──────────────────────────────────────────────────────
  function getFilteredDevices() {
    const query = searchInput.value.toLowerCase().trim();
    const minConfidence = parseInt(confidenceFilter.value, 10);

    const activeProtocols = [];
    protocolFilters.forEach(cb => { if (cb.checked) activeProtocols.push(cb.value); });

    const activeVendors = [];
    vendorFilters.querySelectorAll('input[type="checkbox"]').forEach(cb => {
      if (cb.checked) activeVendors.push(cb.value);
    });

    const activeTypes = [];
    typeFilters.querySelectorAll('input[type="checkbox"]').forEach(cb => {
      if (cb.checked) activeTypes.push(cb.value);
    });

    const activeSubnets = [];
    subnetFilters.querySelectorAll('input[type="checkbox"]').forEach(cb => {
      if (cb.checked) activeSubnets.push(cb.value);
    });

    return devices.filter(d => {
      if (query) {
        const haystack = `${d.ip} ${d.mac} ${d.vendor} ${d.model} ${d.hostname} ${d.subnet_zone || ''} ${displayDeviceType(d)} ${d.asset_class || ''}`.toLowerCase();
        if (!haystack.includes(query)) return false;
      }
      if (d.confidence < minConfidence) return false;
      if (activeProtocols.length > 0 && activeProtocols.length < 4) {
        const dProtos = (d.protocols || []).map(p => p.toUpperCase());
        const hasMatch = dProtos.some(p => activeProtocols.includes(p));
        if (!hasMatch && dProtos.length > 0) return false;
      }
      if (activeVendors.length > 0) {
        if (!activeVendors.some(v => d.vendor === v)) return false;
      }
      if (activeTypes.length > 0) {
        const dtype = displayDeviceType(d);
        if (!activeTypes.includes(dtype)) return false;
      }
      if (activeSubnets.length > 0) {
        if (!activeSubnets.some(s => d.subnet === s)) return false;
      }
      return true;
    });
  }

  function sortDevices(list) {
    return list.sort((a, b) => {
      let va, vb;
      switch(sortField) {
        case 'ip':
          va = a.ip.split('.').map(n => n.padStart(3, '0')).join('');
          vb = b.ip.split('.').map(n => n.padStart(3, '0')).join('');
          break;
        case 'mac': va = a.mac || ''; vb = b.mac || ''; break;
        case 'vendor': va = a.vendor || ''; vb = b.vendor || ''; break;
        case 'model': va = a.model || ''; vb = b.model || ''; break;
        case 'ports': va = (a.open_ports || []).length; vb = (b.open_ports || []).length; break;
        case 'confidence': va = a.confidence; vb = b.confidence; break;
        default: va = a.ip; vb = b.ip;
      }
      if (va < vb) return sortDir === 'asc' ? -1 : 1;
      if (va > vb) return sortDir === 'asc' ? 1 : -1;
      return 0;
    });
  }

  // ─── Detail panel ───────────────────────────────────────────────────
  async function selectDevice(ip) {
    selectedDeviceIp = ip;
    const device = devices.find(d => d.ip === ip);
    if (!device) return;

    detailTitle.textContent = device.ip;
    detailBody.innerHTML = renderDetailPanelContent(device, null);
    detailPanel.classList.add('cam__detail-panel--open');

    $$('.cam__tr').forEach(tr => tr.classList.remove('cam__tr--selected'));
    const row = document.querySelector(`.cam__tr[data-ip="${ip}"]`);
    if (row) row.classList.add('cam__tr--selected');

    // Fetch the Arm-8 "next safe action" asynchronously and inject it
    // without blocking the panel opening.
    try {
      const r = await apiFetch(`/api/devices/${encodeURIComponent(ip)}/next-action`);
      if (r.ok) {
        const na = await r.json();
        const el = document.getElementById('cam-next-action');
        if (el && na.action) {
          el.innerHTML =
            `<span style="color:#7ee787;font-weight:bold">&#8594; Next: </span>` +
            esc(na.action);
          el.style.display = '';
        }
      }
    } catch(_) {}
  }

  function closeDetail() {
    selectedDeviceIp = null;
    detailPanel.classList.remove('cam__detail-panel--open');
    $$('.cam__tr').forEach(tr => tr.classList.remove('cam__tr--selected'));
  }

  function renderDetailPanelContent(device) {
    const sections = [];

    // Arm-8 explainer block \u2014 content injected asynchronously after fetch
    const warnBlock = device.warn_reset
      ? `<div style="background:#2a0d0d;border:1px solid #f85149;border-radius:4px;padding:5px 10px;margin-bottom:6px;font-size:11px;color:#f85149">` +
        `&#9888; <strong>Do not factory-reset</strong> \u2014 this device may be a ${esc(device.device_class || 'critical')} device. Confirm both ends are accessible first.</div>`
      : '';
    const apipaBlock = device.apipa_seen
      ? `<div style="background:#2b1a00;border:1px solid #d29922;border-radius:4px;padding:5px 10px;margin-bottom:6px;font-size:11px;color:#d29922">` +
        `&#9888; APIPA address (169.254.x.x) detected \u2014 likely no DHCP response or isolated segment.</div>`
      : '';
    const gwBlock = device.suspected_old_gateway
      ? `<div style="background:#1a1000;border:1px solid #d29922;border-radius:4px;padding:5px 10px;margin-bottom:6px;font-size:11px;color:#d29922">` +
        `&#8594; Old gateway hint: <strong>${esc(device.suspected_old_gateway)}</strong> \u2014 device may have a static config pointing to its previous subnet.</div>`
      : '';
    const nextActionEl =
      `<div id="cam-next-action" style="background:#0d2a1a;border:1px solid #3fb950;border-radius:4px;padding:5px 10px;margin-bottom:8px;font-size:11px;color:#c9d1d9;display:none"></div>`;

    // Prefix the rendered content with the alert blocks
    const headerHtml = warnBlock + apipaBlock + gwBlock + nextActionEl;

    sections.push({
      title: 'Identity',
      fields: [
        ['Asset ID', device.asset_id || '\u2014'],
        ['Endpoint ID', device.endpoint_id || '\u2014'],
        ['IP Address', device.ip + (device.apipa_seen ? ' <span style="color:#d29922;font-size:10px">APIPA</span>' : '')],
        ['MAC Address', device.mac || '\u2014'],
        ['Serial', device.serial || '\u2014'],
        ['ONVIF UUID', device.onvif_uuid || '\u2014'],
        ['Vendor', device.vendor],
        ['Device Type', displayDeviceType(device)],
        ...(device.asset_class ? [['Asset Class', device.asset_class]] : []),
        ['Type Confidence', `${device.device_type_confidence != null ? device.device_type_confidence : 0}%`],
        ['Model', device.model || '\u2014'],
        ['Hostname', device.hostname || '\u2014'],
        ['Firmware', device.firmware || '—'],
        ['Why this class', device.classification_rationale || '—'],
        ...(device.notes ? [['Notes', esc(device.notes)]] : []),
      ]
    });

    sections.push({
      title: 'Network',
      fields: [
        ['Subnet', device.subnet || '\u2014'],
        ['Subnet Zone', device.subnet_zone || '\u2014'],
        ['IP History', (device.ip_history || []).join(', ') || '\u2014'],
        ['Open Ports', (device.open_ports || []).join(', ') || '\u2014'],
        ['PoE / Link State', device.poe_state || '\u2014'],
        ['Discovery', (device.discovery_methods || []).join(', ')],
        ['Last Seen', device.last_seen ? new Date(device.last_seen).toLocaleString() : '\u2014'],
        ...(device.suspected_old_gateway ? [['Old Gateway', esc(device.suspected_old_gateway)]] : []),
      ]
    });

    sections.push({
      title: 'Protocols',
      fields: [
        ['ONVIF', `${device.onvif_status}${device.onvif_url ? ' \u2014 <a href="'+esc(device.onvif_url)+'" target="_blank">'+esc(device.onvif_url)+'</a>' : ''}`],
        ['RTSP', `${device.rtsp_status}${device.rtsp_url ? ' \u2014 <a href="'+esc(device.rtsp_url)+'" target="_blank">'+esc(device.rtsp_url)+'</a>' : ''}`],
        ['Web UI', device.web_url ? `<a href="${esc(device.web_url)}" target="_blank">${esc(device.web_url)}</a>` : '\u2014'],
        ['Protocols', (device.protocols || []).join(', ')],
      ]
    });

    // DPI section
    if (device.dpi_stages && Object.keys(device.dpi_stages).length > 0) {
      const dpiFields = [['DPI Score', (device.dpi_score != null ? device.dpi_score + '%' : '\u2014')]];
      DPI_STAGES.forEach(stage => {
        const r = device.dpi_stages[stage];
        if (r) {
          const icon = r.status === 'pass' ? '\u2713' : r.status === 'fail' ? '\u2717' : '?';
          dpiFields.push([DPI_LABELS[stage] || stage, `${icon} ${r.detail || r.status}`]);
        }
      });
      sections.push({ title: 'DPI Protocol Stages', fields: dpiFields });
    }

    sections.push({
      title: 'Fingerprint',
      fields: [
        ['Camera Confidence', `${device.confidence}%`],
        ['Vendor Match', device.vendor],
        ...(device.persisted ? [['Persisted Observations', String(device.observation_count || 0)], ['Install State', device.installed_status || '\u2014']] : []),
      ]
    });

    let html = headerHtml;
    sections.forEach(s => {
      html += `<div class="cam__detail-section">
        <div class="cam__detail-section-title">${s.title}</div>
        <dl class="cam__detail-kv">`;
      s.fields.forEach(([label, value]) => {
        html += `<dt>${label}</dt><dd>${value}</dd>`;
      });
      html += '</dl></div>';
    });

    if (device.raw_responses && Object.keys(device.raw_responses).length) {
      html += `<div class="cam__detail-section">
        <div class="cam__detail-section-title">Raw Responses</div>
        <div class="cam__detail-raw"><pre>${esc(JSON.stringify(device.raw_responses, null, 2))}</pre></div>
      </div>`;
    }

    return html;
  }

  // ─── Stats & filters ────────────────────────────────────────────────
  function updateStats() {
    const total = devices.length;
    const cameras = devices.filter(d => displayDeviceType(d) === 'camera' || d.confidence >= 40).length;
    const onvif = devices.filter(d => d.onvif_status === 'found').length;
    const rtsp = devices.filter(d => d.rtsp_status === 'found').length;

    $('#stat-total').textContent = total;
    $('#stat-cameras').textContent = cameras;
    $('#stat-onvif').textContent = onvif;
    $('#stat-rtsp').textContent = rtsp;

    // DPI stats
    const dpiValidated = devices.filter(d => d.dpi_stages && Object.keys(d.dpi_stages).length > 0).length;
    const dpiIssues = devices.filter(d => {
      if (!d.dpi_stages) return false;
      return Object.values(d.dpi_stages).some(s => s.status === 'fail');
    }).length;
    const dpiScores = devices.filter(d => d.dpi_score != null).map(d => d.dpi_score);
    const avgDpi = dpiScores.length ? Math.round(dpiScores.reduce((a,b) => a+b, 0) / dpiScores.length) : null;

    $('#stat-dpi-validated').textContent = dpiValidated;
    $('#stat-dpi-issues').textContent = dpiIssues;
    $('#stat-dpi-avg-score').textContent = avgDpi != null ? avgDpi + '%' : '\u2014';
    $('#stat-subnet-zones').textContent = subnetZones.length;

    updateVendorFilters();
    updateTypeFilters();
    updateSubnetFilters();
    updateProtocolCounts();
  }

  function updateVendorFilters() {
    const vendors = {};
    devices.forEach(d => { vendors[d.vendor] = (vendors[d.vendor] || 0) + 1; });

    const existing = new Set();
    vendorFilters.querySelectorAll('input[type="checkbox"]').forEach(cb => existing.add(cb.value));

    let html = '';
    Object.entries(vendors).sort((a,b) => b[1] - a[1]).forEach(([vendor, count]) => {
      const checked = existing.has(vendor) ? 'checked' : (existing.size === 0 ? 'checked' : '');
      html += `
        <label class="cam__filter-item">
          <input type="checkbox" value="${esc(vendor)}" ${checked}> ${esc(vendor)}
          <span class="cam__filter-count">${count}</span>
        </label>`;
    });
    vendorFilters.innerHTML = html;
    vendorFilters.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.addEventListener('change', renderTable));
  }

  function updateTypeFilters() {
    const counts = {};
    devices.forEach(d => {
      const dtype = displayDeviceType(d);
      counts[dtype] = (counts[dtype] || 0) + 1;
    });

    const existing = new Set();
    typeFilters.querySelectorAll('input[type="checkbox"]').forEach(cb => existing.add(cb.value));

    let html = '';
    Object.entries(counts).sort((a, b) => b[1] - a[1]).forEach(([dtype, count]) => {
      const checked = existing.has(dtype) ? 'checked' : (existing.size === 0 ? 'checked' : '');
      html += `
        <label class="cam__filter-item">
          <input type="checkbox" value="${esc(dtype)}" ${checked}> ${esc(dtype.replace(/_/g, ' '))}
          <span class="cam__filter-count">${count}</span>
        </label>`;
    });
    typeFilters.innerHTML = html;
    typeFilters.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.addEventListener('change', renderTable));
  }

  function updateSubnetFilters() {
    const subnets = {};
    devices.forEach(d => { if (d.subnet) subnets[d.subnet] = (subnets[d.subnet] || 0) + 1; });

    let html = '';
    // Show subnet zones as cards
    subnetZones.forEach(zone => {
      html += `
        <div class="cam__subnet-zone-card">
          <div class="cam__subnet-zone-card__header">
            <span class="cam__subnet-zone-card__subnet">${esc(zone.subnet)}</span>
            <button class="cam__subnet-zone-card__delete" onclick="window._removeSubnet('${esc(zone.subnet)}')">&times;</button>
          </div>
          ${zone.label ? `<div class="cam__subnet-zone-card__label">${esc(zone.label)}</div>` : ''}
          <div class="cam__subnet-zone-card__meta">
            <span>${zone.method}</span>
            <span>${zone.discoverable ? 'discoverable' : 'no discovery'}</span>
            <span>${zone.internet_blocked ? 'internet blocked' : 'internet open'}</span>
          </div>
        </div>`;
    });

    // Also add filter checkboxes for discovered subnets
    Object.entries(subnets).sort((a,b) => b[1] - a[1]).forEach(([subnet, count]) => {
      html += `
        <label class="cam__filter-item">
          <input type="checkbox" value="${esc(subnet)}" checked> ${esc(subnet)}
          <span class="cam__filter-count">${count}</span>
        </label>`;
    });
    subnetFilters.innerHTML = html;
    subnetFilters.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.addEventListener('change', renderTable));
  }

  function updateProtocolCounts() {
    const counts = { ONVIF: 0, RTSP: 0, HTTP: 0, SSDP: 0 };
    devices.forEach(d => {
      (d.protocols || []).forEach(p => {
        const key = p.toUpperCase();
        if (key.includes('ONVIF')) counts.ONVIF++;
        if (key.includes('RTSP')) counts.RTSP++;
        if (key.includes('HTTP')) counts.HTTP++;
        if (key.includes('SSDP') || key.includes('UPNP')) counts.SSDP++;
      });
    });
    $$('.cam__filter-count[data-protocol]').forEach(el => {
      el.textContent = counts[el.dataset.protocol] || 0;
    });
  }

  // ─── Capture Position ───────────────────────────────────────────────
  function renderCapturePosition() {
    const pos = capturePosition.position || 'unknown';
    const labels = {
      wifi: 'Wi-Fi', ethernet_same: 'Ethernet', span_port: 'SPAN Port',
      inline_tap: 'Inline Tap', nvr_capture: 'NVR Capture', unknown: 'Unknown'
    };
    capturePosLabel.textContent = labels[pos] || pos;

    capturePosEl.classList.remove('cam__capture-pos--good', 'cam__capture-pos--limited', 'cam__capture-pos--unknown');
    if (capturePosition.can_see_unicast && capturePosition.can_see_rtsp) {
      capturePosEl.classList.add('cam__capture-pos--good');
    } else if (pos === 'wifi') {
      capturePosEl.classList.add('cam__capture-pos--limited');
    } else {
      capturePosEl.classList.add('cam__capture-pos--unknown');
    }
  }

  function showCapturePositionDialog() {
    const options = [
      { id: 'wifi', icon: '\u{1F4F6}', label: 'Wi-Fi Adapter', desc: 'Limited — broadcast/multicast only, cannot see unicast camera-to-NVR traffic', unicast: false, rtsp: false },
      { id: 'ethernet_same', icon: '\u{1F5A7}', label: 'Ethernet Same VLAN', desc: 'Can see unicast + broadcast if on same VLAN as cameras', unicast: true, rtsp: true },
      { id: 'span_port', icon: '\u{1F50D}', label: 'SPAN/Mirror Port', desc: 'Full visibility via managed switch port mirroring', unicast: true, rtsp: true },
      { id: 'inline_tap', icon: '\u{1F517}', label: 'Inline Tap', desc: 'Full visibility via network tap between switch and NVR', unicast: true, rtsp: true },
      { id: 'nvr_capture', icon: '\u{1F4BB}', label: 'NVR Interface Capture', desc: 'Capture directly on the NVR network interface', unicast: true, rtsp: true },
    ];

    const selected = capturePosition.position;
    let html = `<div class="cam__capture-dialog" onclick="if(event.target===this)this.remove()">
      <div class="cam__capture-dialog__inner">
        <div class="cam__capture-dialog__title">Capture Position</div>
        <p style="font-size:11px;color:var(--text-muted);margin:0 0 12px">Where are you capturing from? This affects what traffic you can see.</p>`;

    options.forEach(o => {
      html += `
        <div class="cam__capture-dialog__option ${o.id === selected ? 'cam__capture-dialog__option--selected' : ''}"
             onclick="window._setCapturePosition('${o.id}')">
          <span class="cam__capture-dialog__option__icon">${o.icon}</span>
          <div class="cam__capture-dialog__option__text">
            <div class="cam__capture-dialog__option__label">${o.label}</div>
            <div class="cam__capture-dialog__option__desc">${o.desc}</div>
          </div>
          <div class="cam__capture-dialog__option__vis">
            <span class="cam__capture-dialog__option__vis-tag ${o.unicast ? 'cam__capture-dialog__option__vis-tag--yes' : 'cam__capture-dialog__option__vis-tag--no'}">Unicast</span>
            <span class="cam__capture-dialog__option__vis-tag ${o.rtsp ? 'cam__capture-dialog__option__vis-tag--yes' : 'cam__capture-dialog__option__vis-tag--no'}">RTSP</span>
          </div>
        </div>`;
    });

    html += `<div class="cam__capture-dialog__actions">
        <button class="cam__subnet-dialog__btn cam__subnet-dialog__btn--cancel" onclick="this.closest('.cam__capture-dialog').remove()">Close</button>
      </div>
    </div></div>`;

    document.body.insertAdjacentHTML('beforeend', html);
  }

  // ─── Subnet Zone Dialog ─────────────────────────────────────────────
  function showAddSubnetDialog() {
    const html = `<div class="cam__subnet-dialog" onclick="if(event.target===this)this.remove()">
      <div class="cam__subnet-dialog__inner">
        <div class="cam__subnet-dialog__title">Add Subnet Zone</div>
        <div class="cam__subnet-dialog__field">
          <label>Subnet (CIDR)</label>
          <input type="text" id="new-subnet" placeholder="192.168.88.0/24">
        </div>
        <div class="cam__subnet-dialog__field">
          <label>Label</label>
          <input type="text" id="new-subnet-label" placeholder="Legacy Camera Range">
        </div>
        <div class="cam__subnet-dialog__field">
          <label>Gateway</label>
          <input type="text" id="new-subnet-gateway" placeholder="192.168.1.1">
        </div>
        <div class="cam__subnet-dialog__field">
          <label>Method</label>
          <select id="new-subnet-method">
            <option value="auto">Auto (try secondary IP, then route)</option>
            <option value="secondary_ip">Secondary IP on this adapter</option>
            <option value="route">Static route via gateway</option>
            <option value="manual">Manual (no auto-configuration)</option>
          </select>
        </div>
        <div class="cam__subnet-dialog__field">
          <label>Notes</label>
          <input type="text" id="new-subnet-notes" placeholder="Previous installer range">
        </div>
        <div class="cam__subnet-dialog__actions">
          <button class="cam__subnet-dialog__btn cam__subnet-dialog__btn--cancel" onclick="this.closest('.cam__subnet-dialog').remove()">Cancel</button>
          <button class="cam__subnet-dialog__btn cam__subnet-dialog__btn--add" onclick="window._addSubnet()">Add Zone</button>
        </div>
      </div>
    </div>`;

    document.body.insertAdjacentHTML('beforeend', html);
  }

  // ─── Activity ticker ────────────────────────────────────────────────
  function addActivityEvent(type, message) {
    const dotClass = type === 'found' ? 'cam__activity-event__dot--found'
                   : type === 'error' ? 'cam__activity-event__dot--error'
                   : type === 'warn' ? 'cam__activity-event__dot--warn'
                   : 'cam__activity-event__dot--idle';

    const time = new Date().toLocaleTimeString();
    activityEvents.push({ type, message, time, dotClass });
    if (activityEvents.length > 50) activityEvents.shift();

    let html = '';
    activityEvents.forEach(e => {
      html += `<span class="cam__activity-event">
        <span class="cam__activity-event__dot ${e.dotClass}"></span>
        ${esc(e.time)} ${esc(e.message)}
      </span>`;
    });
    tickerInner.innerHTML = html;
  }

  // ─── Row expand/collapse ────────────────────────────────────────────
  window._toggleExpand = function(ip) {
    const btn = document.querySelector(`.cam__tr[data-ip="${ip}"] .cam__expand-btn`);
    const detailRow = document.querySelector(`.cam__detail-row[data-detail-ip="${ip}"]`);
    if (!btn || !detailRow) return;
    const isOpen = btn.classList.toggle('cam__expand-btn--open');
    detailRow.style.display = isOpen ? '' : 'none';
  };

  window._selectDevice = function(ip) {
    selectDevice(ip);
  };

  window._validateDPI = async function(ip) {
    addActivityEvent('found', `Running DPI validation on ${ip}...`);
    try {
      const resp = await apiFetch(`/api/dpi/validate/${ip}`);
      const result = await resp.json();
      // Update device in local state
      const idx = devices.findIndex(d => d.ip === ip);
      if (idx >= 0) {
        devices[idx].dpi_stages = result.dpi_stages;
        devices[idx].dpi_score = result.dpi_score;
        devices[idx].dpi_summary = result.dpi_summary;
      }
      renderTable();
      updateStats();
      addActivityEvent('found', `DPI validation complete for ${ip}: ${result.dpi_score}%`);
    } catch(e) {
      addActivityEvent('error', `DPI validation failed for ${ip}`);
    }
  };

  window._setCapturePosition = async function(position) {
    try {
      const resp = await apiFetch('/api/capture-position', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ position }),
      });
      capturePosition = await resp.json();
      renderCapturePosition();
    } catch(e) { /* ignore */ }
    closeAnyDialog();
  };

  window._addSubnet = async function() {
    const subnet = document.getElementById('new-subnet').value.trim();
    const label = document.getElementById('new-subnet-label').value.trim();
    const gateway = document.getElementById('new-subnet-gateway').value.trim();
    const method = document.getElementById('new-subnet-method').value;
    const notes = document.getElementById('new-subnet-notes').value.trim();

    if (!subnet) return;

    try {
      await apiFetch('/api/subnets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ subnet, label, gateway, method, notes }),
      });
      await loadSubnetZones();
      addActivityEvent('found', `Added subnet zone: ${subnet}`);
    } catch(e) {
      addActivityEvent('error', `Failed to add subnet zone`);
    }
    closeAnyDialog();
  };

  window._removeSubnet = async function(subnet) {
    try {
      await apiFetch(`/api/subnets/${encodeURIComponent(subnet)}`, { method: 'DELETE' });
      await loadSubnetZones();
      addActivityEvent('warn', `Removed subnet zone: ${subnet}`);
    } catch(e) { /* ignore */ }
  };

  // ─── Camera Viewer ──────────────────────────────────────────────────────
  window._viewCamera = async function(ip) {
    const device = devices.find(d => d.ip === ip) || { ip };

    // Load saved credentials
    let savedUser = 'admin', savedPass = '';
    try {
      const credsResp = await apiFetch(`/api/devices/${encodeURIComponent(ip)}/credentials`);
      if (credsResp.ok) {
        const creds = await credsResp.json();
        savedUser = creds.username || 'admin';
        // Backend intentionally never returns the plaintext password.  We keep
        // a renderer-memory cache for the current session so clicking
        // "Save & Load" actually applies the credentials the operator just typed.
        savedPass = viewerPasswordCache[ip] || '';
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
    // Keep the password in renderer memory for this session so reopening the
    // viewer does not force the operator to re-type it every time.
    viewerPasswordCache[ip] = pass;
    try {
      await apiFetch(`/api/devices/${encodeURIComponent(ip)}/credentials`, {
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

  window._setViewerMode = async function(ip, mode) {
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
      const streamUrl = await authenticatedMediaUrl(`/api/devices/${encodeURIComponent(ip)}/stream?user=${encodeURIComponent(user)}&pass=${encodeURIComponent(pass)}`);
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
      const resp = await apiFetch(`/api/devices/${encodeURIComponent(ip)}/onvif-info?user=${encodeURIComponent(user)}&pass=${encodeURIComponent(pass)}&timeout=6`);
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

  window._refreshSnapshot = async function(ip) {
    const img   = document.getElementById('viewer-img');
    const errEl = document.getElementById('viewer-snap-error');
    if (!img) return;
    const user = (document.getElementById('viewer-user') || {}).value || 'admin';
    const pass = (document.getElementById('viewer-pass') || {}).value || '';
    const ts   = Date.now();
    const url  = await authenticatedMediaUrl(`/api/devices/${encodeURIComponent(ip)}/snapshot?user=${encodeURIComponent(user)}&pass=${encodeURIComponent(pass)}&_=${ts}`);
    img.src = '';
    img.style.opacity = '0.4';
    if (errEl) errEl.style.display = 'none';
    const tester = new Image();
    tester.onload  = () => { img.src = url; img.style.opacity = '1'; };
    tester.onerror = () => { img.style.opacity = '0'; if (errEl) errEl.style.display = ''; };
    tester.src = url;
  };

  // ─── Set IP Dialog ──────────────────────────────────────────────────
  window._showSetIPDialog = function(ip) {
    const device = devices.find(d => d.ip === ip) || { ip };
    const subnet = device.subnet || '';
    const defaultGw = subnet ? subnet.replace(/\d+\/\d+$/, '1') : '';

    const html = `<div class="cam__setip-dialog" onclick="if(event.target===this)this.remove()">
      <div class="cam__setip-dialog__inner">
        <div class="cam__setip-dialog__title">&#9998; Propose IP Change &mdash; ${esc(ip)}</div>
        <div class="cam__setip-info">
          <span class="cam__vendor-badge ${getVendorClass(device.vendor || '')}">${esc(device.vendor || 'Unknown')}</span>
          MAC: ${esc(device.mac || '—')}
        </div>
        <div class="cam__setip-field">
          <label>New IP Address</label>
          <input type="text" id="setip-newip" placeholder="192.168.1.50" value="${esc(ip)}" class="cam__setip-input">
        </div>
        <div class="cam__setip-field">
          <label>Subnet Mask</label>
          <input type="text" id="setip-mask" placeholder="255.255.255.0" value="255.255.255.0" class="cam__setip-input">
        </div>
        <div class="cam__setip-field">
          <label>Default Gateway</label>
          <input type="text" id="setip-gw" placeholder="192.168.1.1" value="${esc(defaultGw)}" class="cam__setip-input">
        </div>
        <div class="cam__setip-result" id="setip-result" style="display:none"></div>
        <div class="cam__setip-actions">
          <button class="cam__subnet-dialog__btn cam__subnet-dialog__btn--cancel" onclick="this.closest('.cam__setip-dialog').remove()">Cancel</button>
          <button class="cam__subnet-dialog__btn cam__subnet-dialog__btn--add" id="setip-submit-btn" onclick="window._submitSetIP('${esc(ip)}')">Propose Plan</button>
        </div>
      </div>
    </div>`;

    closeAnyDialog();
    document.body.insertAdjacentHTML('beforeend', html);
    document.getElementById('setip-newip').focus();
  };

  window._submitSetIP = async function(ip) {
    const newIp   = document.getElementById('setip-newip').value.trim();
    const netmask = document.getElementById('setip-mask').value.trim();
    const gateway = document.getElementById('setip-gw').value.trim();
    const resultEl = document.getElementById('setip-result');
    const btn = document.getElementById('setip-submit-btn');
    const device = devices.find(d => d.ip === ip) || {};

    if (!newIp) { resultEl.textContent = 'New IP is required.'; resultEl.style.display = ''; return; }

    btn.disabled = true;
    btn.textContent = 'Proposing...';
    resultEl.style.display = 'none';

    try {
      if (!currentSiteId || !device.endpoint_id) {
        throw new Error('Bind a site and reconcile this device before proposing a governed IP change.');
      }
      const resp = await apiFetch('/api/change-plans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          site_id: currentSiteId,
          endpoint_id: device.endpoint_id,
          new_ip: newIp,
          mask: netmask,
          gateway,
          user_id: 'operator',
        }),
      });
      const result = await resp.json();
      resultEl.style.display = '';
      if (result.job_id) {
        resultEl.className = 'cam__setip-result cam__setip-result--ok';
        resultEl.textContent = `Plan ${result.job_id} proposed (${result.status}). Approve and execute it from the governed workflow.`;
        addActivityEvent('found', `IP change plan proposed for ${ip} -> ${newIp}`);
      } else if (result.success) {
        resultEl.className = 'cam__setip-result cam__setip-result--ok';
        resultEl.textContent = `✓ ${result.message || 'IP change sent. Camera may reboot.'}`;
        addActivityEvent('found', `IP change sent to ${ip} → ${newIp} (${result.method})`);
      } else {
        resultEl.className = 'cam__setip-result cam__setip-result--err';
        resultEl.textContent = `✗ ${result.message || 'Failed — check credentials and try again'}`;
        addActivityEvent('error', `IP change failed for ${ip}: ${result.message}`);
      }
    } catch(e) {
      resultEl.style.display = '';
      resultEl.className = 'cam__setip-result cam__setip-result--err';
      resultEl.textContent = e.message || 'Unable to create governed change plan.';
    }
    btn.disabled = false;
    btn.textContent = 'Propose Plan';
  };

  function closeAnyDialog() {
    document.querySelectorAll('.cam__subnet-dialog, .cam__capture-dialog, .cam__setip-dialog, .cam__viewer-overlay').forEach(d => d.remove());
  }

  // ─── Utilities ──────────────────────────────────────────────────────
  // (esc is defined at module scope — line 12 — no duplicate needed)

  function debounce(fn, ms) {
    let timer;
    return function(...args) {
      clearTimeout(timer);
      timer = setTimeout(() => fn.apply(this, args), ms);
    };
  }

  // ─── Boot ───────────────────────────────────────────────────────────
  async function safeInit() {
    try {
      await init();
    } catch(e) {
      console.error('CAM INIT FAILED:', e);
      document.body.insertAdjacentHTML('afterbegin',
        `<div style="position:fixed;top:0;left:0;right:0;z-index:9999;background:#ff3a3a;color:#fff;padding:10px 16px;font:13px monospace;">
          Init error: ${e.message} — open DevTools (F12) for details
        </div>`
      );
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', safeInit);
  } else {
    safeInit();
  }

})();
