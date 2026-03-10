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

<h1>Audit Log</h1>

{#if error}
  <p class="error">Error: {error} <button onclick={() => error = null}>dismiss</button></p>
{/if}

<div class="filters">
  <label>Action <input bind:value={filterAction} placeholder="e.g. login_success" /></label>
  <label>User ID <input bind:value={filterUserId} placeholder="Filter by user" /></label>
  <button class="btn primary" onclick={load}>Filter</button>
</div>

{#if loading}
  <p>Loading...</p>
{:else}
  <table>
    <thead>
      <tr><th>Time</th><th>Action</th><th>User ID</th><th>IP</th><th>Detail</th></tr>
    </thead>
    <tbody>
      {#each events as event}
        <tr>
          <td>{event.timestamp}</td>
          <td><span class="badge">{event.action}</span></td>
          <td class="mono">{event.user_id ? event.user_id.slice(0, 8) + '...' : '-'}</td>
          <td>{event.ip_address}</td>
          <td class="mono truncate">{JSON.stringify(event.detail)}</td>
        </tr>
      {/each}
    </tbody>
  </table>
  {#if events.length === 0}
    <p>No audit events found.</p>
  {/if}
{/if}

<style>
  .filters {
    display: flex; gap: 1rem; align-items: end; margin-bottom: 1rem;
    background: white; padding: 1rem; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);
  }
  .filters label { display: flex; flex-direction: column; gap: 0.25rem; }
  .filters input { padding: 0.5rem; border: 1px solid #ccc; border-radius: 4px; }
  table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
  th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid #eee; }
  th { background: #f9f9f9; font-weight: 600; }
  .mono { font-family: monospace; font-size: 0.85rem; }
  .truncate { max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .badge { background: #e3f2fd; color: #1565c0; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.85rem; }
  .btn { padding: 0.4rem 0.8rem; border: 1px solid #ccc; border-radius: 4px; cursor: pointer; background: white; }
  .btn.primary { background: #0f3460; color: white; border-color: #0f3460; }
  .error { color: red; background: #fff0f0; padding: 0.5rem 1rem; border-radius: 4px; }
</style>
