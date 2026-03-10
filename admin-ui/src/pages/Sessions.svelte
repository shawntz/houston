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

<div class="page-header">
  <h1>Sessions</h1>
  <p class="page-desc">Active user sessions.</p>
</div>

{#if error}
  <div class="alert alert-destructive">
    <span>{error}</span>
    <button class="btn btn-ghost btn-sm" onclick={() => error = null}>Dismiss</button>
  </div>
{/if}

{#if loading}
  <div class="loading">Loading...</div>
{:else}
  <div class="card table-wrapper">
    <table>
      <thead>
        <tr>
          <th>User ID</th>
          <th>IP Address</th>
          <th>User Agent</th>
          <th>Created</th>
          <th>Expires</th>
          <th class="actions-col">Actions</th>
        </tr>
      </thead>
      <tbody>
        {#each sessions as session}
          <tr>
            <td class="mono">{session.user_id.slice(0, 8)}...</td>
            <td>{session.ip_address}</td>
            <td class="truncate">{session.user_agent}</td>
            <td class="muted">{session.created_at}</td>
            <td class="muted">{session.expires_at}</td>
            <td class="actions-col">
              <button class="btn btn-destructive btn-sm" onclick={() => handleRevoke(session.id)}>Revoke</button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
    {#if sessions.length === 0}
      <div class="empty-state">
        <p class="muted">No active sessions.</p>
      </div>
    {/if}
  </div>
{/if}

<style>
  .page-header { margin-bottom: 1.5rem; }
  .page-header h1 { font-size: 1.5rem; font-weight: 700; letter-spacing: -0.025em; color: hsl(var(--foreground)); }
  .page-desc { color: hsl(var(--muted-foreground)); font-size: 0.875rem; margin-top: 0.25rem; }

  .loading { color: hsl(var(--muted-foreground)); font-size: 0.875rem; padding: 2rem; }

  .alert-destructive {
    display: flex; justify-content: space-between; align-items: center;
    background: hsl(var(--destructive) / 0.1); color: hsl(var(--destructive));
    border: 1px solid hsl(var(--destructive) / 0.2); padding: 0.75rem 1rem;
    border-radius: var(--radius); font-size: 0.875rem; margin-bottom: 1rem;
  }

  .card { background: hsl(var(--card)); border: 1px solid hsl(var(--border)); border-radius: var(--radius); }
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

  .mono { font-family: 'SF Mono', SFMono-Regular, ui-monospace, monospace; font-size: 0.8125rem; }
  .muted { color: hsl(var(--muted-foreground)); }
  .truncate { max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .empty-state { padding: 2rem; text-align: center; }

  .btn {
    display: inline-flex; align-items: center; justify-content: center;
    font-family: inherit; font-size: 0.875rem; font-weight: 500;
    padding: 0.5rem 1rem; border-radius: var(--radius); cursor: pointer;
    transition: background-color 0.15s; border: 1px solid transparent; outline: none;
  }
  .btn-sm { padding: 0.25rem 0.625rem; font-size: 0.8125rem; }
  .btn-destructive { background: hsl(var(--destructive)); color: hsl(var(--destructive-foreground)); }
  .btn-destructive:hover { opacity: 0.9; }
  .btn-ghost { background: transparent; color: inherit; }
  .btn-ghost:hover { background: hsl(var(--accent)); }
</style>
