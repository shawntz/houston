<script lang="ts">
  import { listSessions, revokeSession } from '../lib/api';

  let sessions: any[] = $state([]);
  let loading = $state(true);
  let error: string | null = $state(null);

  async function load() {
    try {
      loading = true;
      sessions = await listSessions();
    } catch (e: any) {
      error = e.message;
    } finally {
      loading = false;
    }
  }

  async function handleRevoke(id: string) {
    if (!confirm('Revoke this session?')) return;
    try {
      await revokeSession(id);
      await load();
    } catch (e: any) {
      error = e.message;
    }
  }

  $effect(() => { load(); });
</script>

<h1>Sessions</h1>

{#if error}
  <p class="error">Error: {error} <button onclick={() => error = null}>dismiss</button></p>
{/if}

{#if loading}
  <p>Loading...</p>
{:else}
  <table>
    <thead>
      <tr><th>User ID</th><th>IP</th><th>User Agent</th><th>Created</th><th>Expires</th><th>Actions</th></tr>
    </thead>
    <tbody>
      {#each sessions as session}
        <tr>
          <td class="mono">{session.user_id.slice(0, 8)}...</td>
          <td>{session.ip_address}</td>
          <td class="truncate">{session.user_agent}</td>
          <td>{session.created_at}</td>
          <td>{session.expires_at}</td>
          <td><button class="btn danger" onclick={() => handleRevoke(session.id)}>Revoke</button></td>
        </tr>
      {/each}
    </tbody>
  </table>
  {#if sessions.length === 0}
    <p>No active sessions.</p>
  {/if}
{/if}

<style>
  table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
  th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid #eee; }
  th { background: #f9f9f9; font-weight: 600; }
  .mono { font-family: monospace; }
  .truncate { max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .btn { padding: 0.4rem 0.8rem; border: 1px solid #ccc; border-radius: 4px; cursor: pointer; background: white; }
  .btn.danger { background: #dc3545; color: white; border-color: #dc3545; }
  .error { color: red; background: #fff0f0; padding: 0.5rem 1rem; border-radius: 4px; }
</style>
