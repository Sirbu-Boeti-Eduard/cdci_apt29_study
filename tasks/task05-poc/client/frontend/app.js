async function post(path) {
  const response = await fetch(path, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: '{}'
  });
  const value = await response.json();
  if (!response.ok) throw new Error(value.error || 'Request failed');
  return value;
}

let renderedVersion = null;

function render(state) {
  if (!state || !state.version) return;
  if (renderedVersion !== null && renderedVersion !== state.version) {
    document.getElementById('action-message').textContent = '';
  }
  renderedVersion = state.version;
  const manifest = state.manifest || {};
  const config = manifest.client_config || {};
  const update = state.update || {};
  document.getElementById('version').textContent = state.version.toUpperCase();
  document.getElementById('release-notes').textContent = manifest.release_notes || '';
  document.body.classList.toggle('theme-midnight', config.theme === 'midnight');
  document.getElementById('topology').hidden = config.topology !== true;
  document.getElementById('health-summary').hidden = config.health_summary !== true;
  document.getElementById('update-badge').textContent = update.state || 'Checking channel';
  document.getElementById('update-message').textContent = update.message || 'The update agent is checking the stable channel.';
  document.getElementById('update-progress').style.width = `${Math.max(0, Math.min(100, Number(update.percent) || 0))}%`;
  document.getElementById('install-update').hidden = update.state !== 'available';
  document.getElementById('last-check').textContent = update.last_check ? `Last checked ${new Date(update.last_check).toLocaleTimeString()}` : '';
  document.getElementById('history').textContent = (state.history || [])
    .map(event => `${event.time}  ${event.message}`).join('\n') || 'No update activity yet.';
}

async function refresh() {
  try {
    const response = await fetch('/api/state');
    const state = await response.json();
    if (!response.ok) throw new Error(state.error || 'Update service unavailable');
    render(state);
  } catch (error) {
    document.getElementById('action-message').textContent = error.message;
  }
}

document.getElementById('check-now').addEventListener('click', async () => {
  try {
    const result = await post('/api/check-updates');
    document.getElementById('action-message').textContent = result.message;
    await refresh();
  } catch (error) {
    document.getElementById('action-message').textContent = error.message;
  }
});

document.getElementById('install-update').addEventListener('click', async () => {
  try {
    const result = await post('/api/install-update');
    document.getElementById('action-message').textContent = result.message;
    await refresh();
  } catch (error) {
    document.getElementById('action-message').textContent = error.message;
  }
});

refresh();
setInterval(refresh, 500);
