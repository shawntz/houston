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

<h1>Apps</h1>

{#if error}
  <p class="error">Error: {error} <button onclick={() => error = null}>dismiss</button></p>
{/if}

<button class="btn primary" onclick={() => showCreate = !showCreate}>
  {showCreate ? 'Cancel' : 'Register App'}
</button>

{#if showCreate}
  <div class="form-card">
    <h3>New App</h3>
    <label>Name <input bind:value={form.name} /></label>
    <label>Protocol
      <select bind:value={form.protocol}>
        <option value="oidc">OIDC</option>
        <option value="saml">SAML</option>
      </select>
    </label>
    {#if form.protocol === 'oidc'}
      <label>Redirect URIs (one per line) <textarea bind:value={form.redirect_uris}></textarea></label>
    {:else}
      <label>Entity ID <input bind:value={form.entity_id} /></label>
      <label>ACS URL <input bind:value={form.acs_url} /></label>
    {/if}
    <button class="btn primary" onclick={handleCreate}>Create</button>
  </div>
{/if}

{#if loading}
  <p>Loading...</p>
{:else}
  <table>
    <thead>
      <tr><th>Name</th><th>Protocol</th><th>Client ID / Entity ID</th><th>Actions</th></tr>
    </thead>
    <tbody>
      {#each apps as app}
        <tr>
          <td>{app.name}</td>
          <td>{app.protocol.toUpperCase()}</td>
          <td>{app.client_id || app.entity_id || '-'}</td>
          <td>
            {#if app.protocol === 'oidc'}
              <button class="btn" onclick={() => handleRotate(app.id)}>Rotate ID</button>
            {/if}
            <button class="btn danger" onclick={() => handleDelete(app.id)}>Delete</button>
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
{/if}

<style>
  .form-card {
    background: white; padding: 1.5rem; border-radius: 8px; margin: 1rem 0;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1); display: flex; flex-direction: column;
    gap: 0.5rem; max-width: 400px;
  }
  .form-card label { display: flex; flex-direction: column; gap: 0.25rem; }
  .form-card input, .form-card select, .form-card textarea {
    padding: 0.5rem; border: 1px solid #ccc; border-radius: 4px;
  }
  .form-card textarea { min-height: 60px; }
  table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-top: 1rem; }
  th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid #eee; }
  th { background: #f9f9f9; font-weight: 600; }
  .btn { padding: 0.4rem 0.8rem; border: 1px solid #ccc; border-radius: 4px; cursor: pointer; background: white; }
  .btn.primary { background: #0f3460; color: white; border-color: #0f3460; }
  .btn.danger { background: #dc3545; color: white; border-color: #dc3545; }
  .error { color: red; background: #fff0f0; padding: 0.5rem 1rem; border-radius: 4px; }
</style>
