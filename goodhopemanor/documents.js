'use strict';
/** Accessible guest documents and least-privilege staff dashboard. */
const state = {category: 'all', csrf: null, role: null, username: null, documents: [], users: []};
const el = (id) => document.getElementById(id);
function notice(message, kind = '') {
  const output = el('adminStatus');
  output.textContent = message;
  output.className = 'form-status ' + kind;
}
function safeDate(value) {
  if (!value) return '';
  const dt = new Date(value + 'T00:00:00');
  return Number.isNaN(dt.getTime()) ? '' : dt.toLocaleDateString();
}
function node(tag, text = '', className = '') {
  const result = document.createElement(tag);
  result.textContent = text;
  if (className) result.className = className;
  return result;
}
function link(url, label, className = 'mini-btn') {
  const result = node('a', label, className);
  result.href = url;
  return result;
}
function button(label, callback) {
  const result = node('button', label, 'mini-btn');
  result.type = 'button';
  result.addEventListener('click', callback);
  return result;
}
async function api(endpoint, options = {}) {
  const headers = {...(options.headers || {})};
  if (options.body && !(options.body instanceof FormData))
    headers['Content-Type'] = 'application/json';
  if (state.csrf && ['POST', 'PATCH', 'DELETE'].includes((options.method || 'GET').toUpperCase()))
    headers['x-csrf-token'] = state.csrf;
  const response = await fetch(endpoint, {...options, headers, credentials: 'same-origin'});
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || 'An error occurred.');
  return body;
}
function show(name) {
  for (const id of ['loginPanel', 'passwordPanel', 'resetPanel', 'adminTools'])
    el(id).hidden = id !== name;
}
async function refreshPublic() {
  const container = el('publicDocuments');
  container.replaceChildren();
  try {
    let docs = (await api('/api/documents/public')).documents;
    if (state.category !== 'all') docs = docs.filter((x) => x.category === state.category);
    if (!docs.length) {
      const card = node('article', '', 'doc-card');
      card.append(
        node('h3', 'No approved documents are currently available.'),
        node('p', 'Please check back later or contact Good Hope Manor.'),
      );
      container.append(card);
      return;
    }
    for (const d of docs) {
      const card = node('article', '', 'doc-card');
      card.append(node('h3', d.title), node('small', d.category));
      const date = node('p');
      date.append(node('span', `Last updated: ${new Date(d.updatedAt).toLocaleDateString()}`));
      if (d.effectiveDate) date.append(node('span', ` • Effective: ${safeDate(d.effectiveDate)}`));
      if (d.expirationDate) date.append(node('span', ` • Expires: ${safeDate(d.expirationDate)}`));
      card.append(
        date,
        link(
          `/api/documents/${encodeURIComponent(d.id)}/download`,
          'View / Download',
          'button button--ghost',
        ),
      );
      container.append(card);
    }
  } catch {
    container.append(
      node('p', 'Documents are temporarily unavailable. Please contact Good Hope Manor.'),
    );
  }
}
async function refreshSession() {
  try {
    const data = await api('/api/auth/session');
    state.csrf = data.csrfToken || null;
    state.role = data.role || null;
    state.username = data.username || null;
    if (location.hash.startsWith('#reset=')) {
      show('resetPanel');
      return;
    }
    if (!data.authenticated) {
      show('loginPanel');
      return;
    }
    if (data.forcePasswordChange) {
      show('passwordPanel');
      return;
    }
    show('adminTools');
    el('signedInUser').textContent = `Signed in: ${state.username} (${state.role})`;
    document.querySelectorAll('[data-for-roles]').forEach((section) => {
      section.hidden = !section.dataset.forRoles.split(' ').includes(state.role);
    });
    await refreshAdmin();
  } catch {
    show('loginPanel');
  }
}
async function refreshAdmin() {
  const payload = await api('/api/admin/documents');
  state.documents = payload.documents;
  const container = el('adminDocuments');
  container.replaceChildren();
  const chooser = el('replaceDocSelect');
  chooser.replaceChildren();
  for (const d of state.documents) {
    chooser.add(new Option(`${d.title} (v${d.version})`, d.id));
    const row = node('div', '', 'admin-doc-row');
    row.append(
      node('strong', `${d.title} — v${d.version}`),
      node(
        'span',
        `${d.category} • ${d.approved ? 'Approved' : 'Not approved'} • ${d.archived ? 'Archived' : 'Active'}`,
      ),
    );
    const actions = node('div', '', 'row-actions');
    actions.append(link(`/api/admin/documents/${d.id}/versions/${d.version}/download`, 'Download'));
    if (['admin', 'approver'].includes(state.role))
      actions.append(
        button(d.approved ? 'Unapprove' : 'Approve', () =>
          actDocument(d.id, d.approved ? 'unapprove' : 'approve'),
        ),
      );
    if (['admin', 'editor'].includes(state.role)) {
      actions.append(
        button(d.archived ? 'Unarchive' : 'Archive', () =>
          actDocument(d.id, d.archived ? 'unarchive' : 'archive'),
        ),
      );
      actions.append(button('Edit dates/title', () => editDocument(d)));
    }
    actions.append(button('Version history', () => showVersions(row, d.id)));
    if (state.role === 'admin')
      actions.append(
        button('Delete', async () => {
          if (
            confirm(
              `Delete ${d.title} from public and admin listings? Versions remain in restricted storage for retention.`,
            )
          )
            await actDocument(d.id, 'delete');
        }),
      );
    row.append(actions);
    container.append(row);
  }
  if (!state.documents.length) container.append(node('p', 'No documents have been uploaded yet.'));
  if (state.role === 'admin') {
    await refreshUsers();
    await refreshAudit();
  }
}
async function actDocument(id, action) {
  try {
    const method = action === 'delete' ? 'DELETE' : 'PATCH';
    await api(`/api/admin/documents/${id}`, {
      method,
      ...(method === 'PATCH' ? {body: JSON.stringify({action})} : {}),
    });
    notice('Document updated.', 'success');
    await refreshAdmin();
    await refreshPublic();
  } catch (error) {
    notice(error.message, 'error');
  }
}
async function editDocument(d) {
  const title = prompt('Document title', d.title);
  if (title === null) return;
  const exp = prompt('Expiration date (YYYY-MM-DD), or blank', d.expirationDate || '');
  if (exp === null) return;
  try {
    await api(`/api/admin/documents/${d.id}`, {
      method: 'PATCH',
      body: JSON.stringify({action: 'metadata', title, expirationDate: exp}),
    });
    notice('Metadata saved; approval reset for review.', 'success');
    await refreshAdmin();
    await refreshPublic();
  } catch (error) {
    notice(error.message, 'error');
  }
}
async function showVersions(row, id) {
  try {
    const result = await api(`/api/admin/documents/${id}/versions`);
    const list = node('ul');
    for (const version of result.versions) {
      const item = node('li');
      item.append(
        link(
          `/api/admin/documents/${id}/versions/${version.version}/download`,
          `Version ${version.version} • ${version.original_name} • ${safeDate(version.created_at.slice(0, 10))}`,
        ),
      );
      list.append(item);
    }
    row.append(list);
  } catch (error) {
    notice(error.message, 'error');
  }
}
async function refreshUsers() {
  const result = await api('/api/admin/users');
  const box = el('adminUsers');
  box.replaceChildren();
  for (const user of result.users) {
    const line = node('div', '', 'admin-doc-row');
    line.append(
      node('strong', `${user.username} — ${user.email}`),
      node('span', `${user.role} • ${user.disabled ? 'Disabled' : 'Active'}`),
    );
    const actions = node('div', '', 'row-actions');
    actions.append(button('Invite / reset password', () => resetUser(user)));
    actions.append(
      button(user.disabled ? 'Enable' : 'Disable', async () => {
        if (!confirm(`Change access for ${user.username}?`)) return;
        try {
          await api(`/api/admin/users/${user.id}`, {
            method: 'PATCH',
            body: JSON.stringify({disabled: !user.disabled}),
          });
          await refreshUsers();
          notice('User updated.', 'success');
        } catch (e) {
          notice(e.message, 'error');
        }
      }),
    );
    for (const role of ['admin', 'editor', 'approver']) {
      if (role === user.role) continue;
      actions.append(
        button(`Make ${role}`, async () => {
          if (!confirm(`Assign ${role} permissions to ${user.username}?`)) return;
          try {
            await api(`/api/admin/users/${user.id}`, {
              method: 'PATCH',
              body: JSON.stringify({role}),
            });
            await refreshUsers();
            notice('Role updated.', 'success');
          } catch (e) {
            notice(e.message, 'error');
          }
        }),
      );
    }
    line.append(actions);
    box.append(line);
  }
}
function showInvite(data, email) {
  const output = el('newUserResult');
  output.replaceChildren();
  output.append(
    node(
      'p',
      data.emailSent
        ? 'Invitation sent by configured email provider.'
        : 'Email is not configured or delivery was unavailable. Share this single-use invitation link securely.',
    ),
  );
  if (data.invitationUrl) {
    const field = node('input');
    field.type = 'text';
    field.readOnly = true;
    field.value = data.invitationUrl;
    field.setAttribute('aria-label', 'One-time invitation URL');
    output.append(field);
    output.append(
      button('Copy invitation link', () => navigator.clipboard?.writeText(data.invitationUrl)),
    );
    output.append(
      link(
        `mailto:${encodeURIComponent(email)}?subject=${encodeURIComponent('Good Hope Manor account invitation')}&body=${encodeURIComponent('Here is your one-time password setup link (expires in 30 minutes):\n' + data.invitationUrl)}`,
        'Create email draft',
      ),
    );
  }
}
async function resetUser(u) {
  try {
    const result = await api(`/api/admin/users/${u.id}/reset`, {method: 'POST', body: '{}'});
    showInvite(result, u.email);
    notice('Invitation generated.', 'success');
  } catch (e) {
    notice(e.message, 'error');
  }
}
async function refreshAudit() {
  const result = await api('/api/admin/audit');
  const list = el('auditEvents');
  list.replaceChildren();
  for (const entry of result.events.slice(0, 30))
    list.append(node('p', `${new Date(entry.createdAt).toLocaleString()} — ${entry.event}`));
}
function registerEvents() {
  document.querySelectorAll('.doc-filter').forEach((b) =>
    b.addEventListener('click', () => {
      document.querySelectorAll('.doc-filter').forEach((x) => x.classList.remove('active'));
      b.classList.add('active');
      state.category = b.dataset.category;
      refreshPublic();
    }),
  );
  el('loginForm').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const fields = new FormData(ev.currentTarget);
    try {
      await api('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({username: fields.get('username'), password: fields.get('password')}),
      });
      ev.currentTarget.reset();
      notice('Login successful.', 'success');
      await refreshSession();
    } catch (e) {
      notice(e.message, 'error');
    }
  });
  el('changePasswordForm').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const fields = new FormData(ev.currentTarget);
    try {
      await api('/api/auth/change-password', {
        method: 'POST',
        body: JSON.stringify({newPassword: fields.get('newPassword')}),
      });
      ev.currentTarget.reset();
      notice('Password changed.', 'success');
      await refreshSession();
    } catch (e) {
      notice(e.message, 'error');
    }
  });
  el('resetForm').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const fields = new FormData(ev.currentTarget);
    const token = decodeURIComponent(location.hash.slice('#reset='.length));
    try {
      await api('/api/auth/reset-password', {
        method: 'POST',
        body: JSON.stringify({token, newPassword: fields.get('newPassword')}),
      });
      history.replaceState(null, '', location.pathname);
      ev.currentTarget.reset();
      notice('Password set. You can now log in.', 'success');
      await refreshSession();
    } catch (e) {
      notice(e.message, 'error');
    }
  });
  el('selfPasswordForm').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const form = new FormData(ev.currentTarget);
    try {
      await api('/api/auth/change-password', {
        method: 'POST',
        body: JSON.stringify({
          oldPassword: form.get('oldPassword'),
          newPassword: form.get('newPassword'),
        }),
      });
      ev.currentTarget.reset();
      notice('Password updated; other sessions were revoked.', 'success');
    } catch (e) {
      notice(e.message, 'error');
    }
  });
  el('logoutButton').addEventListener('click', async () => {
    try {
      await api('/api/auth/logout', {method: 'POST', body: '{}'});
      state.csrf = null;
      notice('Logged out.', 'success');
      await refreshSession();
    } catch (e) {
      notice(e.message, 'error');
    }
  });
  el('uploadForm').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    try {
      await api('/api/admin/documents', {method: 'POST', body: new FormData(ev.currentTarget)});
      ev.currentTarget.reset();
      notice('Uploaded privately as a draft. An approver must approve it for guests.', 'success');
      await refreshAdmin();
    } catch (e) {
      notice(e.message, 'error');
    }
  });
  el('replaceForm').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const data = new FormData(ev.currentTarget),
      id = data.get('documentId');
    try {
      await api(`/api/admin/documents/${encodeURIComponent(id)}/versions`, {
        method: 'POST',
        body: data,
      });
      ev.currentTarget.reset();
      notice('Replacement uploaded; guest approval has been reset.', 'success');
      await refreshAdmin();
      await refreshPublic();
    } catch (e) {
      notice(e.message, 'error');
    }
  });
  el('createUserForm').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const form = new FormData(ev.currentTarget),
      details = Object.fromEntries(form);
    try {
      const result = await api('/api/admin/users', {method: 'POST', body: JSON.stringify(details)});
      showInvite(result, details.email);
      ev.currentTarget.reset();
      notice('Account created.', 'success');
      await refreshUsers();
    } catch (e) {
      notice(e.message, 'error');
    }
  });
}
registerEvents();
refreshPublic();
refreshSession();
