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

<div class="page-header">
  <h1>Dashboard</h1>
  <p class="page-desc">Overview of your identity provider.</p>
</div>

{#if loading}
  <div class="loading">Loading...</div>
{:else if error}
  <div class="alert alert-destructive">
    <p>{error}</p>
  </div>
{:else}
  <div class="stats">
    <div class="card stat-card">
      <div class="stat-label">Users</div>
      <div class="stat-value">{userCount}</div>
    </div>
    <div class="card stat-card">
      <div class="stat-label">Apps</div>
      <div class="stat-value">{appCount}</div>
    </div>
    <div class="card stat-card">
      <div class="stat-label">Active Sessions</div>
      <div class="stat-value">{sessionCount}</div>
    </div>
  </div>

  <div class="section">
    <h2>Recent Events</h2>
    {#if recentEvents.length === 0}
      <div class="card empty-state">
        <p class="muted">No audit events yet.</p>
      </div>
    {:else}
      <div class="card table-wrapper">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Action</th>
              <th>User ID</th>
              <th>IP</th>
            </tr>
          </thead>
          <tbody>
            {#each recentEvents as event}
              <tr>
                <td class="muted">{event.timestamp}</td>
                <td><span class="badge">{event.action}</span></td>
                <td class="mono">{event.user_id || '\u2014'}</td>
                <td class="muted">{event.ip_address}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </div>
{/if}

<style>
  .page-header { margin-bottom: 1.5rem; }
  .page-header h1 {
    font-size: 1.5rem;
    font-weight: 700;
    letter-spacing: -0.025em;
    color: hsl(var(--foreground));
  }
  .page-desc {
    color: hsl(var(--muted-foreground));
    font-size: 0.875rem;
    margin-top: 0.25rem;
  }

  .loading {
    color: hsl(var(--muted-foreground));
    font-size: 0.875rem;
    padding: 2rem;
  }

  .alert-destructive {
    background: hsl(var(--destructive) / 0.1);
    color: hsl(var(--destructive));
    border: 1px solid hsl(var(--destructive) / 0.2);
    padding: 0.75rem 1rem;
    border-radius: var(--radius);
    font-size: 0.875rem;
    margin-bottom: 1.5rem;
  }

  .stats {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 1rem;
    margin-bottom: 2rem;
  }

  .card {
    background: hsl(var(--card));
    border: 1px solid hsl(var(--border));
    border-radius: var(--radius);
  }

  .stat-card {
    padding: 1.5rem;
  }
  .stat-label {
    font-size: 0.875rem;
    font-weight: 500;
    color: hsl(var(--muted-foreground));
  }
  .stat-value {
    font-size: 2rem;
    font-weight: 700;
    letter-spacing: -0.025em;
    color: hsl(var(--foreground));
    margin-top: 0.25rem;
  }

  .section { margin-top: 1.5rem; }
  .section h2 {
    font-size: 1.125rem;
    font-weight: 600;
    color: hsl(var(--foreground));
    margin-bottom: 0.75rem;
  }

  .table-wrapper { overflow: hidden; }
  table { width: 100%; border-collapse: collapse; }
  th {
    text-align: left;
    padding: 0.75rem 1rem;
    font-size: 0.75rem;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: hsl(var(--muted-foreground));
    border-bottom: 1px solid hsl(var(--border));
  }
  td {
    padding: 0.75rem 1rem;
    font-size: 0.875rem;
    border-bottom: 1px solid hsl(var(--border));
  }
  tbody tr:last-child td { border-bottom: none; }

  .badge {
    display: inline-block;
    padding: 0.125rem 0.5rem;
    font-size: 0.75rem;
    font-weight: 500;
    border-radius: 9999px;
    background: hsl(var(--secondary));
    color: hsl(var(--secondary-foreground));
  }
  .mono { font-family: 'SF Mono', SFMono-Regular, ui-monospace, monospace; font-size: 0.8125rem; }
  .muted { color: hsl(var(--muted-foreground)); }
  .empty-state { padding: 2rem; text-align: center; }
</style>
