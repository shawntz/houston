<script lang="ts">
  import { listApps, createApp, deleteApp, rotateAppSecret } from '../lib/api';

  let apps: any[] = $state([]);
  let loading = $state(true);
  let error: string | null = $state(null);
  let showCreate = $state(false);

  let form = $state({
    name: '',
    protocol: 'oidc',
    redirect_uris: '',
    entity_id: '',
    acs_url: '',
  });

  async function load() {
    try {
      loading = true;
      apps = await listApps();
    } catch (e: any) {
      error = e.message;
    } finally {
      loading = false;
    }
  }

  async function handleCreate() {
    try {
      const data: any = { name: form.name, protocol: form.protocol };
      if (form.protocol === 'oidc') {
        data.redirect_uris = form.redirect_uris.split('\n').map((u: string) => u.trim()).filter(Boolean);
      } else {
        data.entity_id = form.entity_id;
        data.acs_url = form.acs_url;
      }
      await createApp(data);
      showCreate = false;
      form = { name: '', protocol: 'oidc', redirect_uris: '', entity_id: '', acs_url: '' };
      await load();
    } catch (e: any) {
      error = e.message;
    }
  }

  async function handleDelete(id: string) {
    if (!confirm('Delete this app?')) return;
    try {
      await deleteApp(id);
      await load();
    } catch (e: any) {
      error = e.message;
    }
  }

  async function handleRotate(id: string) {
    if (!confirm('Rotate client ID? Existing integrations will break.')) return;
    try {
      await rotateAppSecret(id);
      await load();
    } catch (e: any) {
      error = e.message;
    }
  }

  $effect(() => { load(); });
</script>

<div class="page-header">
  <div class="page-header-row">
    <div>
      <h1>Apps</h1>
      <p class="page-desc">Manage OIDC and SAML applications.</p>
    </div>
    <button class="btn btn-primary" onclick={() => showCreate = !showCreate}>
      {showCreate ? 'Cancel' : '+ Register App'}
    </button>
  </div>
</div>

{#if error}
  <div class="alert alert-destructive">
    <span>{error}</span>
    <button class="btn btn-ghost btn-sm" onclick={() => error = null}>Dismiss</button>
  </div>
{/if}

{#if showCreate}
  <div class="card form-card">
    <div class="card-header">
      <h3>New Application</h3>
    </div>
    <div class="card-content">
      <div class="form-fields">
        <div class="field">
          <label for="app-name">Name</label>
          <input id="app-name" type="text" bind:value={form.name} placeholder="My Application" />
        </div>
        <div class="field">
          <label for="app-protocol">Protocol</label>
          <select id="app-protocol" bind:value={form.protocol}>
            <option value="oidc">OIDC</option>
            <option value="saml">SAML</option>
          </select>
        </div>
        {#if form.protocol === 'oidc'}
          <div class="field">
            <label for="app-redirects">Redirect URIs <span class="hint">one per line</span></label>
            <textarea id="app-redirects" bind:value={form.redirect_uris} placeholder="https://app.example.com/callback"></textarea>
          </div>
        {:else}
          <div class="field">
            <label for="app-entity">Entity ID</label>
            <input id="app-entity" type="text" bind:value={form.entity_id} placeholder="urn:example:app" />
          </div>
          <div class="field">
            <label for="app-acs">ACS URL</label>
            <input id="app-acs" type="text" bind:value={form.acs_url} placeholder="https://app.example.com/saml/acs" />
          </div>
        {/if}
      </div>
      <div class="form-actions">
        <button class="btn btn-primary" onclick={handleCreate}>Create App</button>
        <button class="btn btn-outline" onclick={() => showCreate = false}>Cancel</button>
      </div>
    </div>
  </div>
{/if}

{#if loading}
  <div class="loading">Loading...</div>
{:else}
  <div class="card table-wrapper">
    <table>
      <thead>
        <tr>
          <th>Name</th>
          <th>Protocol</th>
          <th>Client ID / Entity ID</th>
          <th class="actions-col">Actions</th>
        </tr>
      </thead>
      <tbody>
        {#each apps as app}
          <tr>
            <td class="font-medium">{app.name}</td>
            <td><span class="badge badge-protocol">{app.protocol.toUpperCase()}</span></td>
            <td class="mono">{app.client_id || app.entity_id || '\u2014'}</td>
            <td class="actions-col">
              {#if app.protocol === 'oidc'}
                <button class="btn btn-outline btn-sm" onclick={() => handleRotate(app.id)}>Rotate ID</button>
              {/if}
              <button class="btn btn-destructive btn-sm" onclick={() => handleDelete(app.id)}>Delete</button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
    {#if apps.length === 0}
      <div class="empty-state">
        <p class="muted">No apps registered.</p>
      </div>
    {/if}
  </div>
{/if}

<style>
  .page-header { margin-bottom: 1.5rem; }
  .page-header h1 { font-size: 1.5rem; font-weight: 700; letter-spacing: -0.025em; color: hsl(var(--foreground)); }
  .page-desc { color: hsl(var(--muted-foreground)); font-size: 0.875rem; margin-top: 0.25rem; }
  .page-header-row { display: flex; justify-content: space-between; align-items: flex-start; }

  .loading { color: hsl(var(--muted-foreground)); font-size: 0.875rem; padding: 2rem; }

  .alert-destructive {
    display: flex; justify-content: space-between; align-items: center;
    background: hsl(var(--destructive) / 0.1); color: hsl(var(--destructive));
    border: 1px solid hsl(var(--destructive) / 0.2); padding: 0.75rem 1rem;
    border-radius: var(--radius); font-size: 0.875rem; margin-bottom: 1rem;
  }

  .card { background: hsl(var(--card)); border: 1px solid hsl(var(--border)); border-radius: var(--radius); }
  .card-header { padding: 1.25rem 1.5rem; border-bottom: 1px solid hsl(var(--border)); }
  .card-header h3 { font-size: 1rem; font-weight: 600; }
  .card-content { padding: 1.5rem; }
  .form-card { margin-bottom: 1.5rem; }

  .form-fields { display: flex; flex-direction: column; gap: 1rem; max-width: 500px; }
  .field { display: flex; flex-direction: column; gap: 0.375rem; }
  .field label { font-size: 0.875rem; font-weight: 500; color: hsl(var(--foreground)); }
  .hint { font-weight: 400; color: hsl(var(--muted-foreground)); }

  .field input, .field select, .field textarea {
    padding: 0.5rem 0.75rem; border: 1px solid hsl(var(--input)); border-radius: var(--radius);
    font-size: 0.875rem; font-family: inherit; background: transparent;
    transition: border-color 0.15s, box-shadow 0.15s; outline: none;
  }
  .field input:focus, .field select:focus, .field textarea:focus {
    border-color: hsl(var(--ring));
    box-shadow: 0 0 0 2px hsl(var(--ring) / 0.2);
  }
  .field textarea { min-height: 80px; resize: vertical; }
  .field input::placeholder, .field textarea::placeholder { color: hsl(var(--muted-foreground)); }

  .form-actions { display: flex; gap: 0.5rem; margin-top: 1.25rem; }

  .btn {
    display: inline-flex; align-items: center; justify-content: center; gap: 0.5rem;
    font-family: inherit; font-size: 0.875rem; font-weight: 500;
    padding: 0.5rem 1rem; border-radius: var(--radius); cursor: pointer;
    transition: background-color 0.15s, color 0.15s, border-color 0.15s;
    border: 1px solid transparent; outline: none;
  }
  .btn:focus-visible { box-shadow: 0 0 0 2px hsl(var(--ring) / 0.2); }
  .btn-sm { padding: 0.25rem 0.625rem; font-size: 0.8125rem; }
  .btn-primary { background: hsl(var(--primary)); color: hsl(var(--primary-foreground)); }
  .btn-primary:hover { opacity: 0.9; }
  .btn-outline { background: transparent; border-color: hsl(var(--input)); color: hsl(var(--foreground)); }
  .btn-outline:hover { background: hsl(var(--accent)); }
  .btn-destructive { background: hsl(var(--destructive)); color: hsl(var(--destructive-foreground)); }
  .btn-destructive:hover { opacity: 0.9; }
  .btn-ghost { background: transparent; color: inherit; }
  .btn-ghost:hover { background: hsl(var(--accent)); }

  .table-wrapper { overflow: hidden; }
  table { width: 100%; border-collapse: collapse; }
  th {
    text-align: left; padding: 0.75rem 1rem; font-size: 0.75rem; font-weight: 500;
    text-transform: uppercase; letter-spacing: 0.05em;
    color: hsl(var(--muted-foreground)); border-bottom: 1px solid hsl(var(--border));
  }
  td { padding: 0.75rem 1rem; font-size: 0.875rem; border-bottom: 1px solid hsl(var(--border)); }
  tbody tr:last-child td { border-bottom: none; }
  tbody tr:hover { background: hsl(var(--muted) / 0.5); }
  .actions-col { text-align: right; white-space: nowrap; }
  .actions-col :global(button + button) { margin-left: 0.375rem; }

  .badge {
    display: inline-block; padding: 0.125rem 0.5rem; font-size: 0.75rem; font-weight: 500;
    border-radius: 9999px; background: hsl(var(--secondary)); color: hsl(var(--muted-foreground));
  }
  .badge-protocol { background: hsl(var(--primary) / 0.1); color: hsl(var(--primary)); font-weight: 600; }

  .mono { font-family: 'SF Mono', SFMono-Regular, ui-monospace, monospace; font-size: 0.8125rem; }
  .font-medium { font-weight: 500; }
  .muted { color: hsl(var(--muted-foreground)); }
  .empty-state { padding: 2rem; text-align: center; }
</style>
