<script lang="ts">
  import Dashboard from './pages/Dashboard.svelte';
  import Users from './pages/Users.svelte';
  import Apps from './pages/Apps.svelte';
  import Sessions from './pages/Sessions.svelte';
  import AuditLog from './pages/AuditLog.svelte';

  let currentPage = $state('dashboard');

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
    return () => window.removeEventListener('hashchange', handler);
  });
</script>

<div class="app">
  <nav class="sidebar">
    <h2 class="logo">minikta</h2>
    <ul>
      <li class:active={currentPage === 'dashboard'}>
        <button onclick={() => navigate('dashboard')}>Dashboard</button>
      </li>
      <li class:active={currentPage === 'users'}>
        <button onclick={() => navigate('users')}>Users</button>
      </li>
      <li class:active={currentPage === 'apps'}>
        <button onclick={() => navigate('apps')}>Apps</button>
      </li>
      <li class:active={currentPage === 'sessions'}>
        <button onclick={() => navigate('sessions')}>Sessions</button>
      </li>
      <li class:active={currentPage === 'audit'}>
        <button onclick={() => navigate('audit')}>Audit Log</button>
      </li>
    </ul>
  </nav>

  <main class="content">
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
  </main>
</div>

<style>
  .app {
    display: flex;
    min-height: 100vh;
  }

  .sidebar {
    width: 220px;
    background: #1a1a2e;
    color: #eee;
    padding: 1rem;
    flex-shrink: 0;
  }

  .logo {
    font-size: 1.4rem;
    margin-bottom: 1.5rem;
    padding-bottom: 0.5rem;
    border-bottom: 1px solid #333;
  }

  .sidebar ul {
    list-style: none;
    padding: 0;
    margin: 0;
  }

  .sidebar li {
    margin-bottom: 0.25rem;
  }

  .sidebar button {
    width: 100%;
    text-align: left;
    background: none;
    border: none;
    color: #ccc;
    padding: 0.5rem 0.75rem;
    border-radius: 4px;
    cursor: pointer;
    font-size: 0.95rem;
  }

  .sidebar button:hover {
    background: #16213e;
  }

  .sidebar li.active button {
    background: #0f3460;
    color: #fff;
  }

  .content {
    flex: 1;
    padding: 2rem;
    background: #f5f5f5;
  }
</style>
