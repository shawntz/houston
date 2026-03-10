<script lang="ts">
  import { listUsers, listApps, listSessions, queryAuditLog } from '../lib/api';

  let userCount = $state(0);
  let appCount = $state(0);
  let sessionCount = $state(0);
  let recentEvents: any[] = $state([]);
  let loading = $state(true);
  let error: string | null = $state(null);

  async function loadDashboard() {
    try {
      loading = true;
      const [users, apps, sessions, events] = await Promise.all([
        listUsers(),
        listApps(),
        listSessions(),
        queryAuditLog({ limit: 10 }),
      ]);
      userCount = users.length;
      appCount = apps.length;
      sessionCount = sessions.length;
      recentEvents = events;
    } catch (e: any) {
      error = e.message;
    } finally {
      loading = false;
    }
  }

  $effect(() => { loadDashboard(); });
</script>

<h1>Dashboard</h1>

{#if loading}
  <p>Loading...</p>
{:else if error}
  <p class="error">Error: {error}</p>
{:else}
  <div class="stats">
    <div class="stat-card">
      <div class="stat-value">{userCount}</div>
      <div class="stat-label">Users</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">{appCount}</div>
      <div class="stat-label">Apps</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">{sessionCount}</div>
      <div class="stat-label">Active Sessions</div>
    </div>
  </div>

  <h2>Recent Events</h2>
  {#if recentEvents.length === 0}
    <p>No audit events yet.</p>
  {:else}
    <table>
      <thead>
        <tr><th>Time</th><th>Action</th><th>User ID</th><th>IP</th></tr>
      </thead>
      <tbody>
        {#each recentEvents as event}
          <tr>
            <td>{event.timestamp}</td>
            <td>{event.action}</td>
            <td>{event.user_id || '-'}</td>
            <td>{event.ip_address}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
{/if}

<style>
  .stats {
    display: flex;
    gap: 1rem;
    margin-bottom: 2rem;
  }
  .stat-card {
    background: white;
    border-radius: 8px;
    padding: 1.5rem;
    min-width: 140px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    text-align: center;
  }
  .stat-value {
    font-size: 2rem;
    font-weight: bold;
    color: #0f3460;
  }
  .stat-label {
    color: #666;
    margin-top: 0.25rem;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    background: white;
    border-radius: 8px;
    overflow: hidden;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
  }
  th, td {
    padding: 0.75rem 1rem;
    text-align: left;
    border-bottom: 1px solid #eee;
  }
  th { background: #f9f9f9; font-weight: 600; }
  .error { color: red; }
</style>
