async function post(path, data = {}) {
  const response = await fetch(path, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(data)
  });
  const value = await response.json();
  if (!response.ok) throw new Error(value.error || 'Request failed');
  return value;
}

function message(value) {
  document.getElementById('pipeline-message').textContent = value || '';
}

function escapeHtml(value) {
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function renderLog(lines) {
  const html = lines.map(line => {
    const safe = escapeHtml(line);
    return safe.replace(/^(\d{2}:\d{2}:\d{2}) (INFO|WARN|ERROR)/, '<span class="log-time">$1</span> <span class="log-$2">$2</span>');
  }).join('\n');
  document.getElementById('build-log').innerHTML = html || 'No pipeline activity yet.';
}

function renderReleases(catalog) {
  const releases = Array.isArray(catalog.releases) ? catalog.releases : [];
  document.getElementById('channel-generation').textContent = `Generation ${catalog.generation || 0}`;
  document.getElementById('published-count').textContent = `${releases.length} release${releases.length === 1 ? '' : 's'}`;
  document.getElementById('releases').innerHTML = releases.map(release => `
    <tr>
      <td><strong>${release.version.toUpperCase()}</strong></td>
      <td>${release.artifact}</td>
      <td>${release.mandatory ? 'Mandatory rollout' : 'Available'}</td>
      <td><code>${release.sha256}</code></td>
    </tr>`).join('') || '<tr><td colspan="4">No releases are published.</td></tr>';
}

function renderArtifact(artifact, catalog) {
  const published = (catalog.releases || []).some(item => item.version === 'v3');
  const state = document.getElementById('artifact-state');
  if (published) {
    state.textContent = 'V3 published';
  } else if (!artifact) {
    state.textContent = 'No artifact';
  } else if (artifact.signed) {
    state.textContent = 'Signed';
  } else {
    state.textContent = 'Uploaded';
  }
  document.getElementById('artifact-source').textContent = artifact ? artifact.source_filename : '-';
  document.getElementById('artifact-name').textContent = artifact ? artifact.artifact : 'Not uploaded';
  document.getElementById('artifact-digest').textContent = artifact ? artifact.sha256 : '-';
  document.getElementById('artifact-size').textContent = artifact ? `${artifact.size} bytes` : '-';
  document.getElementById('artifact-signature').textContent = artifact && artifact.signed ? artifact.signature : 'Not signed';
  document.getElementById('artifact-manifest').textContent = artifact
    ? JSON.stringify(artifact.manifest, null, 2)
    : 'No artifact uploaded.';
  document.getElementById('upload-artifact').disabled = published || Boolean(artifact && artifact.signed);
  document.getElementById('sign-artifact').disabled = !artifact || artifact.signed || published;
  document.getElementById('publish-artifact').disabled = !artifact || !artifact.signed || published;
  document.getElementById('rollout').disabled = published;
  if (published) {
    message('V3 is published. The channel is immutable until a presenter reset.');
  }
}

async function refresh() {
  try {
    const response = await fetch('/api/state');
    const state = await response.json();
    if (!response.ok) throw new Error(state.error || 'Release state unavailable');
    renderReleases(state.catalog || {});
    renderArtifact(state.artifact, state.catalog || {});
    renderLog(state.build_log || []);
  } catch (error) {
    message(error.message);
  }
}

document.getElementById('upload-artifact').addEventListener('click', async () => {
  const file = document.getElementById('artifact-file').files[0];
  if (!file) return message('Choose a V3 ZIP artifact first.');
  try {
    const bytes = new Uint8Array(await file.arrayBuffer());
    let binary = '';
    for (let index = 0; index < bytes.length; index += 0x8000) {
      binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000));
    }
    const result = await post('/api/upload-artifact', {filename: file.name, content_base64: btoa(binary)});
    message(result.message);
    await refresh();
  } catch (error) {
    message(error.message);
  }
});

document.getElementById('sign-artifact').addEventListener('click', async () => {
  try {
    const result = await post('/api/sign-artifact');
    message(result.message);
    await refresh();
  } catch (error) {
    message(error.message);
  }
});

document.getElementById('publish-artifact').addEventListener('click', async () => {
  try {
    const result = await post('/api/publish-artifact', {rollout: document.getElementById('rollout').value});
    message(result.message);
    await refresh();
  } catch (error) {
    message(error.message);
  }
});

refresh();
setInterval(refresh, 500);
