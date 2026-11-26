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

function renderArtifact(artifact) {
  document.getElementById('artifact-source').textContent = artifact ? artifact.source_filename : '-';
  document.getElementById('artifact-name').textContent = artifact ? artifact.artifact : 'Not built';
  document.getElementById('artifact-digest').textContent = artifact ? artifact.sha256 : '-';
  document.getElementById('artifact-size').textContent = artifact ? `${artifact.size} bytes` : '-';
  document.getElementById('artifact-signature').textContent = artifact && artifact.signed ? artifact.signature : 'Not signed';
  document.getElementById('artifact-manifest').textContent = artifact
    ? JSON.stringify(artifact.manifest, null, 2)
    : 'No artifact yet.';
}

function renderPipeline(pipeline) {
  const stages = pipeline && Array.isArray(pipeline.stages) ? pipeline.stages : [];
  const total = stages.length || 6;
  const done = stages.filter(stage => stage.status === 'done').length;
  const running = Boolean(pipeline && pipeline.state === 'running');
  const finished = Boolean(pipeline && pipeline.state === 'done');
  const state = document.getElementById('pipeline-state');
  state.textContent = !pipeline ? 'Idle'
    : pipeline.state === 'running' ? 'Running'
    : pipeline.state === 'done' ? 'Published'
    : pipeline.state === 'error' ? 'Failed' : 'Idle';
  document.getElementById('pipeline-bar').style.width = `${Math.round((done / total) * 100)}%`;
  document.getElementById('run-pipeline').disabled = running || finished;
  document.getElementById('rollout').disabled = running || finished;
  if (!stages.length) {
    document.getElementById('pipeline-steps').innerHTML = '<p class="muted">No pipeline run yet.</p>';
    return;
  }
  document.getElementById('pipeline-steps').innerHTML = stages.map(stage => `
    <div class="step ${stage.status}">
      <span class="step-dot"></span>
      <div class="step-body"><strong>${escapeHtml(stage.name)}</strong><small>${escapeHtml(stage.detail || stage.status)}</small></div>
      <span class="step-time">${escapeHtml(stage.finished_at || stage.started_at || '')}</span>
    </div>`).join('');
  message(pipeline.message || '');
}

async function refresh() {
  try {
    const response = await fetch('/api/state');
    const state = await response.json();
    if (!response.ok) throw new Error(state.error || 'Release state unavailable');
    renderReleases(state.catalog || {});
    renderArtifact(state.artifact);
    renderPipeline(state.pipeline || null);
    renderLog(state.build_log || []);
  } catch (error) {
    message(error.message);
  }
}

document.getElementById('run-pipeline').addEventListener('click', async () => {
  try {
    const result = await post('/api/pipeline', {rollout: document.getElementById('rollout').value});
    message(result.message);
    await refresh();
  } catch (error) {
    message(error.message);
  }
});

refresh();
setInterval(refresh, 500);
