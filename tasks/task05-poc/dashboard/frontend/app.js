function escapeHtml(value) {
  return String(value ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function setMessage(value) {
  document.getElementById('message').textContent = value || '';
}

function renderContainers(containers) {
  const items = Array.isArray(containers) ? containers : [];
  document.getElementById('count').textContent = String(items.length);
  document.getElementById('containers').innerHTML = items.length
    ? items.map(container => `
      <tr>
        <td><strong>${escapeHtml(container.name)}</strong></td>
        <td><span class="status running"><i></i>${escapeHtml(container.status)}</span></td>
      </tr>`).join('')
    : '<tr><td colspan="2">No running containers.</td></tr>';
}

const CHAIN_PORTS = {
  build: '8080',
  delivery: '8081',
  install: '8081',
  c2: '8082',
  tasking: '8082',
  detection: '8084',
  response: '8084'
};

function renderKillchain(chain) {
  const phases = chain && Array.isArray(chain.phases) ? chain.phases : [];
  const done = phases.filter(phase => phase.state === 'done').length;
  document.getElementById('chain-count').textContent = `${done}/${phases.length || 7}`;
  document.getElementById('chain').innerHTML = phases.map((phase, index) => {
    const port = CHAIN_PORTS[phase.id] || '8083';
    return `<a class="phase ${escapeHtml(phase.state)}" href="http://${escapeHtml(location.hostname)}:${port}" target="_blank" rel="noopener">
      <span class="phase-index">${String(index + 1).padStart(2, '0')}</span>
      <span class="phase-label">${escapeHtml(phase.label)}</span>
      <span class="phase-state">${escapeHtml(phase.state)}</span>
    </a>`;
  }).join('<span class="phase-arrow">›</span>');
}

async function refresh() {
  try {
    const response = await fetch('/api/state');
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'State unavailable');
    renderContainers(data.containers || []);
    renderKillchain(data.killchain || {});
  } catch (error) {
    setMessage(error.message);
  }
}

document.getElementById('reset-lab').addEventListener('click', async () => {
  const button = document.getElementById('reset-lab');
  button.disabled = true;
  setMessage('Resetting lab...');
  try {
    const response = await fetch('/api/reset', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: '{}'
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Reset failed');
    setMessage(result.message);
    await refresh();
  } catch (error) {
    setMessage(error.message);
  } finally {
    button.disabled = false;
  }
});

refresh();
setInterval(refresh, 1500);
