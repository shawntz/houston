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

<h1>Users</h1>

{#if error}
  <p class="error">Error: {error} <button onclick={() => error = null}>dismiss</button></p>
{/if}

<button class="btn primary" onclick={() => showCreate = !showCreate}>
  {showCreate ? 'Cancel' : 'Create User'}
</button>

{#if showCreate}
  <div class="form-card">
    <h3>New User</h3>
    <label>Username <input bind:value={form.username} /></label>
    <label>Email <input type="email" bind:value={form.email} /></label>
    <label>Display Name <input bind:value={form.display_name} /></label>
    <label>Password <input type="password" bind:value={form.password} /></label>
    <label><input type="checkbox" bind:checked={form.is_admin} /> Admin</label>
    <button class="btn primary" onclick={handleCreate}>Create</button>
  </div>
{/if}

{#if loading}
  <p>Loading...</p>
{:else}
  <table>
    <thead>
      <tr><th>Username</th><th>Email</th><th>Display Name</th><th>Admin</th><th>TOTP</th><th>Actions</th></tr>
    </thead>
    <tbody>
      {#each users as user}
        {#if editingId === user.id}
          <tr>
            <td>{user.username}</td>
            <td><input bind:value={editForm.email} /></td>
            <td><input bind:value={editForm.display_name} /></td>
            <td><input type="checkbox" bind:checked={editForm.is_admin} /></td>
            <td>{user.has_totp ? 'Yes' : 'No'}</td>
            <td>
              <button class="btn" onclick={handleUpdate}>Save</button>
              <button class="btn" onclick={() => editingId = null}>Cancel</button>
            </td>
          </tr>
        {:else}
          <tr>
            <td>{user.username}</td>
            <td>{user.email}</td>
            <td>{user.display_name}</td>
            <td>{user.is_admin ? 'Yes' : 'No'}</td>
            <td>{user.has_totp ? 'Yes' : 'No'}</td>
            <td>
              <button class="btn" onclick={() => startEdit(user)}>Edit</button>
              <button class="btn danger" onclick={() => handleDelete(user.id)}>Delete</button>
            </td>
          </tr>
        {/if}
      {/each}
    </tbody>
  </table>
{/if}

<style>
  .form-card {
    background: white;
    padding: 1.5rem;
    border-radius: 8px;
    margin: 1rem 0;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    max-width: 400px;
  }
  .form-card label { display: flex; flex-direction: column; gap: 0.25rem; }
  .form-card input[type="text"], .form-card input[type="email"], .form-card input[type="password"] {
    padding: 0.5rem;
    border: 1px solid #ccc;
    border-radius: 4px;
  }
  table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-top: 1rem; }
  th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid #eee; }
  th { background: #f9f9f9; font-weight: 600; }
  .btn { padding: 0.4rem 0.8rem; border: 1px solid #ccc; border-radius: 4px; cursor: pointer; background: white; }
  .btn.primary { background: #0f3460; color: white; border-color: #0f3460; }
  .btn.danger { background: #dc3545; color: white; border-color: #dc3545; }
  .error { color: red; background: #fff0f0; padding: 0.5rem 1rem; border-radius: 4px; }
</style>
