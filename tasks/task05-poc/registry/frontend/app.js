const escapeHtml = value => String(value ?? '')
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

function message(value) {
  document.getElementById('message').textContent = value || '';
}

function renderPackages(state) {
  const packages = Array.isArray(state.packages) ? state.packages : [];
  const rows = [];
  for (const pkg of packages) {
    for (const version of pkg.versions || []) {
      rows.push(`
        <tr>
          <td><strong>${escapeHtml(pkg.name)}</strong></td>
          <td class="mono">${escapeHtml(version.version)}</td>
          <td>${escapeHtml(version.description)}</td>
          <td class="mono">${escapeHtml(version.published_at)}</td>
          <td class="mono">${escapeHtml(version.downloads)}</td>
          <td><a href="/api/packages/${encodeURIComponent(pkg.name)}/${encodeURIComponent(version.version)}/archive">zip</a></td>
        </tr>`);
    }
  }
  document.getElementById('count').textContent = String(rows.length);
  document.getElementById('packages').innerHTML = rows.length
    ? rows.join('')
    : '<tr><td colspan="6">No packages yet.</td></tr>';
}

async function refresh() {
  try {
    const response = await fetch('/api/state', {cache: 'no-store'});
    const state = await response.json();
    if (!response.ok) throw new Error(state.error || 'state unavailable');
    renderPackages(state);
  } catch (error) {
    message(error.message);
  }
}

document.getElementById('publish-form').addEventListener('submit', async event => {
  event.preventDefault();
  try {
    const response = await fetch('/api/publish', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        name: document.getElementById('package-name').value.trim(),
        version: document.getElementById('package-version').value.trim(),
        description: document.getElementById('package-description').value.trim(),
      }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'publish failed');
    message(result.message);
    await refresh();
  } catch (error) {
    message(error.message);
  }
});

refresh();
setInterval(refresh, 2000);
