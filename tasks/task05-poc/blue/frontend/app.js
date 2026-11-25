let latest = null;
let query = '';
let rangeSeconds = 0;
let clockOffset = null;
const expanded = new Set();
const lastHtml = {};

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function text(value) {
  return value === undefined || value === null || value === '' ? '-' : String(value);
}

function setMessage(value, tone) {
  const node = document.getElementById('message');
  node.textContent = value || '';
  node.dataset.tone = tone || '';
}

function inWindow(ts) {
  if (!rangeSeconds) return true;
  if (ts === null || ts === undefined || ts === '') return true;
  const value = Number(ts);
  if (!Number.isFinite(value)) return true;
  return Date.now() / 1000 - value <= rangeSeconds;
}

function clockSeconds(value) {
  const match = /^(\d{2}):(\d{2}):(\d{2})$/.exec(String(value || ''));
  if (!match) return null;
  return Number(match[1]) * 3600 + Number(match[2]) * 60 + Number(match[3]);
}

function inferClockOffset() {
  const rows = [];
  if (latest && Array.isArray(latest.alerts)) rows.push(...latest.alerts);
  if (latest && Array.isArray(latest.decodes)) rows.push(...latest.decodes);
  for (const row of rows) {
    const ts = Number(row && row.ts);
    const timeOfDay = clockSeconds(row && row.time);
    if (!Number.isFinite(ts) || timeOfDay === null) continue;
    const epochOfDay = ((ts % 86400) + 86400) % 86400;
    let offset = timeOfDay - epochOfDay;
    if (offset > 43200) offset -= 86400;
    if (offset < -43200) offset += 86400;
    return offset;
  }
  return null;
}

function clockEpoch(value, reference, offset) {
  const timeOfDay = clockSeconds(value);
  if (timeOfDay === null || offset === null) return null;
  let epoch = Math.floor(reference / 86400) * 86400 + timeOfDay - offset;
  if (epoch - reference > 43200) epoch -= 86400;
  if (reference - epoch > 43200) epoch += 86400;
  return epoch;
}

function matches(search) {
  const needle = query.trim().toLowerCase();
  return !needle || search.toLowerCase().includes(needle);
}

function setCount(id, visible, total) {
  document.getElementById(id).textContent = visible === total ? String(total) : `${visible}/${total}`;
}

function commit(key, body, html) {
  if (lastHtml[key] === html) return;
  body.innerHTML = html;
  lastHtml[key] = html;
}

function emptyRow(colspan, label) {
  return `<tr class="empty"><td colspan="${colspan}">${escapeHtml(label)}</td></tr>`;
}

function displayAlert(alert) {
  return JSON.stringify(alert || {}, null, 2);
}

function hexDump(hex) {
  if (!hex) return '';
  const bytes = String(hex).trim().split(/\s+/).filter(value => /^[0-9a-f]{2}$/i.test(value));
  if (!bytes.length) return String(hex);
  const lines = [];
  for (let index = 0; index < bytes.length; index += 16) {
    const chunk = bytes.slice(index, index + 16);
    const hexPart = chunk.join(' ').padEnd(47, ' ');
    const ascii = chunk
      .map(value => {
        const code = parseInt(value, 16);
        return code >= 32 && code < 127 ? String.fromCharCode(code) : '.';
      })
      .join('');
    lines.push(`${index.toString(16).padStart(8, '0')}  ${hexPart} |${ascii}|`);
  }
  return lines.join('\n');
}

function safeId(value) {
  return String(value ?? '').replace(/[^a-zA-Z0-9_-]/g, '_');
}

function detailRow(alert, id) {
  const raw = displayAlert(alert);
  const hex = hexDump(alert && alert.hex);
  const packetBytes = Number(alert && alert.packet_bytes) || 0;
  const jsonId = `json-${safeId(id)}`;
  const hexId = `hex-${safeId(id)}`;
  return `
    <tr class="expand"><td colspan="9">
      <div class="expand-inner">
        <div class="block">
          <div class="block-head"><span>alert json</span><button type="button" class="copy" data-copy="${jsonId}">copy</button></div>
          <pre id="${jsonId}">${escapeHtml(raw)}</pre>
        </div>
        <div class="block">
          <div class="block-head"><span>packet ${packetBytes} B</span><button type="button" class="copy" data-copy="${hexId}"${hex ? '' : ' disabled'}>copy</button></div>
          <pre id="${hexId}">${escapeHtml(hex || 'no packet excerpt')}</pre>
        </div>
      </div>
      <div class="expand-foot"><a href="/capture.pcap">capture.pcap</a><span>${escapeHtml(text(id))}</span></div>
    </td></tr>`;
}

function renderEvents() {
  const alerts = Array.isArray(latest && latest.alerts) ? latest.alerts : [];
  const rows = [];
  for (const alert of alerts) {
    if (!inWindow(alert.ts)) continue;
    const id = alert.id ?? '';
    const detail = alert.summary ?? alert.evidence ?? '';
    const search = [
      id, alert.time, alert.iso, alert.rule, alert.name, alert.src, alert.sport,
      alert.dst, alert.dport, alert.protocol, detail, alert.evidence, alert.flow,
      alert.packet_bytes,
    ].join(' ');
    if (!matches(search)) continue;
    const open = expanded.has(String(id));
    rows.push(`
      <tr class="event" data-alert="${escapeHtml(id)}" tabindex="0" role="button" aria-expanded="${open}">
        <td class="mono">${escapeHtml(text(alert.time))}</td>
        <td class="mono rule">${escapeHtml(text(alert.rule))}</td>
        <td class="mono">${escapeHtml(text(alert.src))}</td>
        <td class="mono">${escapeHtml(text(alert.sport))}</td>
        <td class="mono">${escapeHtml(text(alert.dst))}</td>
        <td class="mono">${escapeHtml(text(alert.dport))}</td>
        <td class="mono">${escapeHtml(text(alert.protocol))}</td>
        <td class="mono">${escapeHtml(text(alert.packet_bytes))}</td>
        <td class="detail">${escapeHtml(text(detail))}</td>
      </tr>${open ? detailRow(alert, id) : ''}`);
  }
  const html = rows.length ? rows.join('') : emptyRow(9, 'no matching events');
  commit('events', document.getElementById('alerts'), html);
  setCount('alert-count', rows.length, alerts.length);
}

function renderDecodes() {
  const decodes = Array.isArray(latest && latest.decodes) ? latest.decodes : [];
  const rows = [];
  for (const row of decodes) {
    if (!inWindow(row.ts)) continue;
    const search = [
      row.time, row.ts, row.src, row.hostname, row.username, row.uid, row.mode,
      row.checksum, row.label, row.note, row.count, row.last, row.decode_ok,
    ].join(' ');
    if (!matches(search)) continue;
    rows.push(`
      <tr>
        <td class="mono">${escapeHtml(text(row.time))}</td>
        <td class="mono">${escapeHtml(text(row.src))}</td>
        <td class="mono">${escapeHtml(text(row.hostname))}</td>
        <td>${escapeHtml(text(row.username))}</td>
        <td class="mono">${escapeHtml(text(row.uid))}</td>
        <td class="mono">${escapeHtml(text(row.mode))}</td>
        <td class="mono" title="${escapeHtml(text(row.note))}">${escapeHtml(text(row.checksum))}</td>
        <td class="mono" title="${escapeHtml(text(row.last))}">${escapeHtml(text(row.count))}</td>
      </tr>`);
  }
  const html = rows.length ? rows.join('') : emptyRow(8, 'no matching rows');
  commit('decodes', document.getElementById('decodes'), html);
  setCount('decode-count', rows.length, decodes.length);
}

function renderBeacons() {
  const beacons = Array.isArray(latest && latest.beacons) ? latest.beacons : [];
  const reference = Date.now() / 1000;
  const rows = [];
  for (const row of beacons) {
    if (!inWindow(clockEpoch(row.last, reference, clockOffset))) continue;
    const search = [
      row.src, row.samples, row.intervals, row.mean, row.spread, row.cv,
      row.first, row.last,
    ].join(' ');
    if (!matches(search)) continue;
    rows.push(`
      <tr>
        <td class="mono">${escapeHtml(text(row.src))}</td>
        <td class="mono">${escapeHtml(text(row.samples))}</td>
        <td class="mono">${escapeHtml(text(row.intervals))}</td>
        <td class="mono">${escapeHtml(text(row.mean))}${row.mean === undefined || row.mean === null ? '' : 's'}</td>
        <td class="mono">${escapeHtml(text(row.spread))}${row.spread === undefined || row.spread === null ? '' : 's'}</td>
        <td class="mono">${escapeHtml(text(row.cv))}</td>
        <td class="mono">${escapeHtml(text(row.first))}</td>
        <td class="mono">${escapeHtml(text(row.last))}</td>
      </tr>`);
  }
  const html = rows.length ? rows.join('') : emptyRow(8, 'no matching rows');
  commit('beacons', document.getElementById('beacons'), html);
  setCount('beacon-count', rows.length, beacons.length);
}

function renderFlows() {
  const flows = Array.isArray(latest && latest.flows) ? latest.flows : [];
  const reference = Date.now() / 1000;
  const rows = [];
  for (const flow of flows) {
    if (!inWindow(clockEpoch(flow.last, reference, clockOffset))) continue;
    const search = [
      flow.src, flow.dst, flow.port, flow.protocol, flow.packets, flow.bytes,
      flow.first, flow.last,
    ].join(' ');
    if (!matches(search)) continue;
    rows.push(`
      <tr>
        <td class="mono">${escapeHtml(text(flow.src))}</td>
        <td class="mono">${escapeHtml(text(flow.dst))}</td>
        <td class="mono">${escapeHtml(text(flow.port))}</td>
        <td class="mono">${escapeHtml(text(flow.protocol))}</td>
        <td class="mono">${escapeHtml(text(flow.packets))}</td>
        <td class="mono">${escapeHtml(text(flow.bytes))}</td>
        <td class="mono">${escapeHtml(text(flow.first))}</td>
        <td class="mono">${escapeHtml(text(flow.last))}</td>
      </tr>`);
  }
  const html = rows.length ? rows.join('') : emptyRow(8, 'no matching rows');
  commit('flows', document.getElementById('flows'), html);
  setCount('flow-count', rows.length, flows.length);
}

function renderHost() {
  const host = (latest && latest.host) || {};
  const events = Array.isArray(host.events) ? host.events : [];
  const starts = events.filter(event => event.event === 'start');
  const rows = [];
  for (const event of starts) {
    if (!inWindow(event.ts)) continue;
    const search = [event.time, event.pid, event.ppid, event.user, event.role, event.cmdline].join(' ');
    if (!matches(search)) continue;
    rows.push(`
      <tr>
        <td class="mono">${escapeHtml(text(event.time))}</td>
        <td class="mono">${escapeHtml(text(event.pid))}</td>
        <td class="mono">${escapeHtml(text(event.ppid))}</td>
        <td class="mono">${escapeHtml(text(event.user))}</td>
        <td><span class="role ${escapeHtml(text(event.role))}">${escapeHtml(text(event.role))}</span></td>
        <td class="cmd">${escapeHtml(text(event.cmdline))}</td>
      </tr>`);
  }
  const html = rows.length ? rows.join('') : emptyRow(6, 'no host events yet');
  commit('host', document.getElementById('host'), html);
  setCount('host-count', rows.length, starts.length);
}

function renderRules() {
  const rules = Array.isArray(latest && latest.rules) ? latest.rules : [];
  const rows = [];
  for (const rule of rules) {
    const search = [rule.id, rule.name].join(' ');
    if (!matches(search)) continue;
    rows.push(`
      <tr>
        <td class="id">${escapeHtml(text(rule.id))}</td>
        <td>${escapeHtml(text(rule.name))}</td>
      </tr>`);
  }
  const html = rows.length ? rows.join('') : emptyRow(2, 'no matching rows');
  commit('rules', document.getElementById('rules'), html);
  setCount('rule-count', rows.length, rules.length);
}

function renderStatus() {
  const state = latest || {};
  const sensor = state.sensor || {};
  const resolver = state.resolver || {};
  const isolation = sensor.isolation || {};
  const packets = Number(sensor.packets || 0);

  const tapChip = document.getElementById('chip-tap');
  tapChip.textContent = sensor.running
    ? `tap ${sensor.interface || '-'} ${sensor.management || ''}`.trim()
    : 'tap down';
  tapChip.dataset.state = sensor.running ? 'ok' : 'bad';

  document.getElementById('chip-packets').textContent = `${packets.toLocaleString('en-US')} pkt`;
  const lastChip = document.getElementById('chip-last');
  lastChip.textContent = sensor.last_packet ? `last ${String(sensor.last_packet).slice(11, 19)}z` : 'last -';
  lastChip.dataset.state = sensor.capture_ready ? 'ok' : 'bad';

  const resolverState = document.getElementById('resolver-state');
  resolverState.textContent = resolver.blocked ? 'blocked' : 'open';
  resolverState.title = resolver.mode ? `mode ${resolver.mode}` : '';

  const tapState = document.getElementById('tap-state');
  tapState.textContent = isolation.active ? 'isolated' : 'forwarding';
  tapState.title = isolation.mechanism || isolation.error || '';

  document.querySelectorAll('[data-action="block-dns"]').forEach(node => { node.disabled = Boolean(resolver.blocked); });
  document.querySelectorAll('[data-action="unblock-dns"]').forEach(node => { node.disabled = !resolver.blocked; });
  document.querySelectorAll('[data-action="isolate"]').forEach(node => { node.disabled = Boolean(isolation.active); });
  document.querySelectorAll('[data-action="restore-tap"]').forEach(node => { node.disabled = !isolation.active; });

  if (sensor.error) setMessage(String(sensor.error), 'bad');
}

function renderAll() {
  if (!latest) return;
  clockOffset = inferClockOffset();
  renderStatus();
  renderEvents();
  renderHost();
  renderDecodes();
  renderBeacons();
  renderFlows();
  renderRules();
}

function toggleAlert(id) {
  const key = String(id);
  if (expanded.has(key)) expanded.delete(key);
  else expanded.add(key);
  renderEvents();
}

function copyNode(button) {
  const node = document.getElementById(button.dataset.copy);
  if (!node) return;
  const value = node.textContent;
  const done = () => {
    const previous = button.textContent;
    button.textContent = 'copied';
    setTimeout(() => { button.textContent = previous; }, 900);
  };
  const fallback = () => {
    const area = document.createElement('textarea');
    area.value = value;
    area.style.position = 'fixed';
    area.style.opacity = '0';
    document.body.appendChild(area);
    area.select();
    try { document.execCommand('copy'); done(); } catch (_error) { /* no clipboard */ }
    area.remove();
  };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(value).then(done).catch(fallback);
  } else {
    fallback();
  }
}

async function refresh() {
  try {
    const response = await fetch('/api/state', { cache: 'no-store' });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'state unavailable');
    latest = data;
    renderAll();
  } catch (error) {
    setMessage(error.message, 'bad');
  }
}

async function respond(action) {
  setMessage(`${action} ...`);
  try {
    const response = await fetch('/api/respond', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'request failed');
    setMessage(`${action} ok`);
    await refresh();
  } catch (error) {
    setMessage(error.message, 'bad');
    await refresh();
  }
}

document.getElementById('query').addEventListener('input', event => {
  query = event.target.value;
  renderAll();
});

document.getElementById('range').addEventListener('change', event => {
  rangeSeconds = Number(event.target.value) || 0;
  renderAll();
});

document.querySelectorAll('[data-action]').forEach(node => {
  node.addEventListener('click', () => respond(node.dataset.action));
});

document.getElementById('alerts').addEventListener('click', event => {
  const copy = event.target.closest('[data-copy]');
  if (copy) {
    copyNode(copy);
    return;
  }
  const row = event.target.closest('tr.event');
  if (row) toggleAlert(row.dataset.alert);
});

document.getElementById('alerts').addEventListener('keydown', event => {
  if (event.key !== 'Enter' && event.key !== ' ') return;
  const row = event.target.closest('tr.event');
  if (row && event.target === row) {
    event.preventDefault();
    toggleAlert(row.dataset.alert);
  }
});

refresh();
setInterval(refresh, 1500);
