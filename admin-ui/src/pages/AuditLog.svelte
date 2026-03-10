<script lang="ts">
  import { queryAuditLog } from '../lib/api';

  let events: any[] = $state([]);
  let loading = $state(true);
  let error: string | null = $state(null);
  let filterAction = $state('');
  let filterUserId = $state('');

  async function load() {
    try {
      loading = true;
      const params: any = { limit: 100 };
      if (filterAction) params.action = filterAction;
      if (filterUserId) params.user_id = filterUserId;
      events = await queryAuditLog(params);
    } catch (e: any) {
      error = e.message;
    } finally {
      loading = false;
    }
  }

  $effect(() => { load(); });
</script>

<div class="page-header">
  <h1>Audit Log</h1>
  <p class="page-desc">Security events and activity history.</p>
</div>

{#if error}
  <div class="alert alert-destructive">
    <span>{error}</span>
    <button class="btn btn-ghost btn-sm" onclick={() => error = null}>Dismiss</button>
  </div>
{/if}

<div class="card filter-card">
  <div class="filter-row">
    <div class="field">
      <label for="filter-action">Action</label>
      <input id="filter-action" type="text" bind:value={filterAction} placeholder="e.g. login_success" />
    </div>
    <div class="field">
      <label for="filter-user">User ID</label>
      <input id="filter-user" type="text" bind:value={filterUserId} placeholder="Filter by user" />
    </div>
    <button class="btn btn-primary filter-btn" onclick={load}>Filter</button>
  </div>
</div>

{#if loading}
  <div class="loading">Loading...</div>
{:else}
  <div class="card table-wrapper">
    <table>
      <thead>
        <tr>
          <th>Time</th>
          <th>Action</th>
          <th>User ID</th>
          <th>IP Address</th>
          <th>Detail</th>
        </tr>
      </thead>
      <tbody>
        {#each events as event}
          <tr>
            <td class="muted">{event.timestamp}</td>
            <td><span class="badge">{event.action}</span></td>
            <td class="mono">{event.user_id ? event.user_id.slice(0, 8) + '...' : '\u2014'}</td>
            <td>{event.ip_address}</td>
            <td class="mono truncate">{JSON.stringify(event.detail)}</td>
          </tr>
        {/each}
      </tbody>
    </table>
    {#if events.length === 0}
      <div class="empty-state">
        <p class="muted">No audit events found.</p>
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
  .filter-card { padding: 1rem 1.25rem; margin-bottom: 1rem; }
  .filter-row { display: flex; gap: 1rem; align-items: flex-end; }
  .field { display: flex; flex-direction: column; gap: 0.375rem; }
  .field label { font-size: 0.875rem; font-weight: 500; color: hsl(var(--foreground)); }
  .field input {
    padding: 0.5rem 0.75rem; border: 1px solid hsl(var(--input)); border-radius: var(--radius);
    font-size: 0.875rem; font-family: inherit; background: transparent;
    transition: border-color 0.15s, box-shadow 0.15s; outline: none; min-width: 200px;
  }
  .field input:focus { border-color: hsl(var(--ring)); box-shadow: 0 0 0 2px hsl(var(--ring) / 0.2); }
  .field input::placeholder { color: hsl(var(--muted-foreground)); }

  .filter-btn { align-self: flex-end; }

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

  .badge {
    display: inline-block; padding: 0.125rem 0.5rem; font-size: 0.75rem; font-weight: 500;
    border-radius: 9999px; background: hsl(var(--secondary)); color: hsl(var(--secondary-foreground));
  }
  .mono { font-family: 'SF Mono', SFMono-Regular, ui-monospace, monospace; font-size: 0.8125rem; }
  .muted { color: hsl(var(--muted-foreground)); }
  .truncate { max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .empty-state { padding: 2rem; text-align: center; }

  .btn {
    display: inline-flex; align-items: center; justify-content: center;
    font-family: inherit; font-size: 0.875rem; font-weight: 500;
    padding: 0.5rem 1rem; border-radius: var(--radius); cursor: pointer;
    transition: background-color 0.15s; border: 1px solid transparent; outline: none;
  }
  .btn-sm { padding: 0.25rem 0.625rem; font-size: 0.8125rem; }
  .btn-primary { background: hsl(var(--primary)); color: hsl(var(--primary-foreground)); }
  .btn-primary:hover { opacity: 0.9; }
  .btn-ghost { background: transparent; color: inherit; }
  .btn-ghost:hover { background: hsl(var(--accent)); }
</style>
