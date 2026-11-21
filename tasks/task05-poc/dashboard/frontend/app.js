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

async function refresh() {
  try {
    const response = await fetch('/api/state');
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'State unavailable');
    renderContainers(data.containers || []);
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
setInterval(refresh, 2000);
