<script lang="ts">
  import { listUsers, createUser, updateUser, deleteUser } from '../lib/api';

  let users: any[] = $state([]);
  let loading = $state(true);
  let error: string | null = $state(null);
  let showCreate = $state(false);

  let form = $state({
    username: '',
    email: '',
    display_name: '',
    password: '',
    is_admin: false,
  });

  let editingId: string | null = $state(null);
  let editForm = $state({ email: '', display_name: '', is_admin: false, password: '' });

  async function load() {
    try {
      loading = true;
      users = await listUsers();
    } catch (e: any) {
      error = e.message;
    } finally {
      loading = false;
    }
  }

  async function handleCreate() {
    try {
      await createUser(form);
      showCreate = false;
      form = { username: '', email: '', display_name: '', password: '', is_admin: false };
      await load();
    } catch (e: any) {
      error = e.message;
    }
  }

  function startEdit(user: any) {
    editingId = user.id;
    editForm = { email: user.email, display_name: user.display_name, is_admin: user.is_admin, password: '' };
  }

  async function handleUpdate() {
    if (!editingId) return;
    const data: any = { email: editForm.email, display_name: editForm.display_name, is_admin: editForm.is_admin };
    if (editForm.password) data.password = editForm.password;
    try {
      await updateUser(editingId, data);
      editingId = null;
      await load();
    } catch (e: any) {
      error = e.message;
    }
  }

  async function handleDelete(id: string) {
    if (!confirm('Delete this user?')) return;
    try {
      await deleteUser(id);
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
      <h1>Users</h1>
      <p class="page-desc">Manage identity provider users.</p>
    </div>
    <button class="btn btn-primary" onclick={() => showCreate = !showCreate}>
      {showCreate ? 'Cancel' : '+ Create User'}
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
      <h3>New User</h3>
    </div>
    <div class="card-content">
      <div class="form-grid">
        <div class="field">
          <label for="new-username">Username</label>
          <input id="new-username" type="text" bind:value={form.username} placeholder="johndoe" />
        </div>
        <div class="field">
          <label for="new-email">Email</label>
          <input id="new-email" type="email" bind:value={form.email} placeholder="john@example.com" />
        </div>
        <div class="field">
          <label for="new-display">Display Name</label>
          <input id="new-display" type="text" bind:value={form.display_name} placeholder="John Doe" />
        </div>
        <div class="field">
          <label for="new-password">Password</label>
          <input id="new-password" type="password" bind:value={form.password} />
        </div>
        <div class="field-inline">
          <input id="new-admin" type="checkbox" bind:checked={form.is_admin} />
          <label for="new-admin">Administrator</label>
        </div>
      </div>
      <div class="form-actions">
        <button class="btn btn-primary" onclick={handleCreate}>Create User</button>
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
          <th>Username</th>
          <th>Email</th>
          <th>Display Name</th>
          <th>Admin</th>
          <th>TOTP</th>
          <th class="actions-col">Actions</th>
        </tr>
      </thead>
      <tbody>
        {#each users as user}
          {#if editingId === user.id}
            <tr class="editing-row">
              <td class="mono">{user.username}</td>
              <td><input class="table-input" bind:value={editForm.email} /></td>
              <td><input class="table-input" bind:value={editForm.display_name} /></td>
              <td><input type="checkbox" bind:checked={editForm.is_admin} /></td>
              <td><span class="badge">{user.has_totp ? 'Enabled' : 'Off'}</span></td>
              <td class="actions-col">
                <button class="btn btn-primary btn-sm" onclick={handleUpdate}>Save</button>
                <button class="btn btn-outline btn-sm" onclick={() => editingId = null}>Cancel</button>
              </td>
            </tr>
          {:else}
            <tr>
              <td class="mono font-medium">{user.username}</td>
              <td>{user.email}</td>
              <td>{user.display_name}</td>
              <td><span class="badge" class:badge-active={user.is_admin}>{user.is_admin ? 'Yes' : 'No'}</span></td>
              <td><span class="badge" class:badge-active={user.has_totp}>{user.has_totp ? 'Enabled' : 'Off'}</span></td>
              <td class="actions-col">
                <button class="btn btn-outline btn-sm" onclick={() => startEdit(user)}>Edit</button>
                <button class="btn btn-destructive btn-sm" onclick={() => handleDelete(user.id)}>Delete</button>
              </td>
            </tr>
          {/if}
        {/each}
      </tbody>
    </table>
    {#if users.length === 0}
      <div class="empty-state">
        <p class="muted">No users found.</p>
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

  .form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; max-width: 600px; }
  .field { display: flex; flex-direction: column; gap: 0.375rem; }
  .field label { font-size: 0.875rem; font-weight: 500; color: hsl(var(--foreground)); }
  .field input {
    padding: 0.5rem 0.75rem; border: 1px solid hsl(var(--input)); border-radius: var(--radius);
    font-size: 0.875rem; font-family: inherit; background: transparent;
    transition: border-color 0.15s, box-shadow 0.15s; outline: none;
  }
  .field input:focus {
    border-color: hsl(var(--ring));
    box-shadow: 0 0 0 2px hsl(var(--ring) / 0.2);
  }
  .field input::placeholder { color: hsl(var(--muted-foreground)); }

  .field-inline { display: flex; align-items: center; gap: 0.5rem; grid-column: span 2; }
  .field-inline label { font-size: 0.875rem; font-weight: 500; }
  .field-inline input[type="checkbox"] { width: 1rem; height: 1rem; accent-color: hsl(var(--primary)); }

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
  .editing-row { background: hsl(var(--muted) / 0.5); }
  .actions-col { text-align: right; white-space: nowrap; }
  .actions-col :global(button + button) { margin-left: 0.375rem; }

  .table-input {
    padding: 0.375rem 0.5rem; border: 1px solid hsl(var(--input)); border-radius: var(--radius);
    font-size: 0.875rem; font-family: inherit; background: hsl(var(--background)); width: 100%;
    outline: none;
  }
  .table-input:focus { border-color: hsl(var(--ring)); box-shadow: 0 0 0 2px hsl(var(--ring) / 0.2); }

  .badge {
    display: inline-block; padding: 0.125rem 0.5rem; font-size: 0.75rem; font-weight: 500;
    border-radius: 9999px; background: hsl(var(--secondary)); color: hsl(var(--muted-foreground));
  }
  .badge-active { background: hsl(var(--primary)); color: hsl(var(--primary-foreground)); }

  .mono { font-family: 'SF Mono', SFMono-Regular, ui-monospace, monospace; font-size: 0.8125rem; }
  .font-medium { font-weight: 500; }
  .muted { color: hsl(var(--muted-foreground)); }
  .empty-state { padding: 2rem; text-align: center; }
</style>
