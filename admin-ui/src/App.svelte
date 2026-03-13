<script lang="ts">
  import Dashboard from './pages/Dashboard.svelte';
  import Users from './pages/Users.svelte';
  import Apps from './pages/Apps.svelte';
  import Sessions from './pages/Sessions.svelte';
  import AuditLog from './pages/AuditLog.svelte';
  import { getVersion } from './lib/api';

  let currentPage = $state('dashboard');
  let version = $state('');

  function navigate(page: string) {
    currentPage = page;
    window.location.hash = page;
  }

  $effect(() => {
    const hash = window.location.hash.slice(1);
    if (hash) currentPage = hash;

    const handler = () => {
      const h = window.location.hash.slice(1);
      if (h) currentPage = h;
    };
    window.addEventListener('hashchange', handler);

    getVersion().then(v => version = v.version).catch(() => {});

    return () => window.removeEventListener('hashchange', handler);
  });

  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: '⊞' },
    { id: 'users', label: 'Users', icon: '⊡' },
    { id: 'apps', label: 'Apps', icon: '⊟' },
    { id: 'sessions', label: 'Sessions', icon: '⊙' },
    { id: 'audit', label: 'Audit Log', icon: '⊘' },
  ];
</script>

<div class="app">
  <aside class="sidebar">
    <div class="sidebar-header">
      <span class="logo">houston</span>
    </div>
    <nav class="sidebar-nav">
      {#each navItems as item}
        <button
          class="nav-item"
          class:active={currentPage === item.id}
          onclick={() => navigate(item.id)}
        >
          <span class="nav-icon">{item.icon}</span>
          {item.label}
        </button>
      {/each}
    </nav>
    <div class="sidebar-footer">
      <form method="POST" action="/logout">
        <button type="submit" class="nav-item logout-btn">Sign out</button>
      </form>
      {#if version}
        <div class="sidebar-version">v{version}</div>
      {/if}
    </div>
  </aside>

  <main class="content">
    <div class="content-inner">
      {#if currentPage === 'dashboard'}
        <Dashboard />
      {:else if currentPage === 'users'}
        <Users />
      {:else if currentPage === 'apps'}
        <Apps />
      {:else if currentPage === 'sessions'}
        <Sessions />
      {:else if currentPage === 'audit'}
        <AuditLog />
      {/if}
    </div>
  </main>
</div>

<style>
  .app {
    display: flex;
    min-height: 100vh;
  }

  .sidebar {
    width: 240px;
    background: hsl(var(--card));
    border-right: 1px solid hsl(var(--border));
    display: flex;
    flex-direction: column;
    flex-shrink: 0;
  }

  .sidebar-header {
    padding: 1.5rem 1.25rem;
    border-bottom: 1px solid hsl(var(--border));
  }

  .logo {
    font-size: 1.125rem;
    font-weight: 700;
    letter-spacing: -0.025em;
    color: hsl(var(--foreground));
  }

  .sidebar-nav {
    flex: 1;
    padding: 0.75rem;
    display: flex;
    flex-direction: column;
    gap: 0.125rem;
  }

  .nav-item {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    width: 100%;
    text-align: left;
    background: none;
    border: none;
    color: hsl(var(--muted-foreground));
    padding: 0.5rem 0.75rem;
    border-radius: var(--radius);
    cursor: pointer;
    font-size: 0.875rem;
    font-weight: 500;
    transition: background-color 0.15s, color 0.15s;
    font-family: inherit;
  }

  .nav-item:hover {
    background: hsl(var(--accent));
    color: hsl(var(--accent-foreground));
  }

  .nav-item.active {
    background: hsl(var(--secondary));
    color: hsl(var(--secondary-foreground));
    font-weight: 600;
  }

  .nav-icon {
    font-size: 1rem;
    width: 1.25rem;
    text-align: center;
    opacity: 0.7;
  }

  .sidebar-footer {
    padding: 0.75rem;
    border-top: 1px solid hsl(var(--border));
  }

  .logout-btn {
    color: hsl(var(--muted-foreground));
    font-size: 0.875rem;
  }

  .sidebar-version {
    padding: 0.5rem 0.75rem 0;
    font-size: 0.6875rem;
    color: hsl(var(--muted-foreground));
    opacity: 0.5;
  }

  .content {
    flex: 1;
    background: hsl(var(--muted));
    overflow-y: auto;
  }

  .content-inner {
    max-width: 1200px;
    padding: 2rem;
  }
</style>
