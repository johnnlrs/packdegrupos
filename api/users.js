const { requirePackProfile } = require('./_lib/authorization');
const { authAdmin } = require('./_lib/firebaseAdmin');
const { callAppsScript } = require('./_lib/appsScript');

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ status: 'error', message: 'Método não permitido.' });
  }
  try {
    const { data } = await requirePackProfile(req, ['admin']);
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : (req.body || {});
    const auth = authAdmin();
    const originalUsers = Array.isArray(data.users) ? data.users.slice() : [];
    let users = originalUsers.slice();
    const action = String(body.action || '');

    if (action === 'create') {
      const u = body.user || {};
      const email = String(u.email || '').trim().toLowerCase();
      const password = String(u.password || '');
      const name = String(u.name || '').trim();
      const whatsapp = String(u.whatsapp || '').trim();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 6 || !name || !whatsapp) {
        return res.status(400).json({ status: 'error', message: 'Informe nome, e-mail válido, WhatsApp e senha com pelo menos 6 caracteres.' });
      }
      let record;
      try {
        record = await auth.createUser({ email, password, displayName: name.slice(0, 100), disabled: false });
        await auth.setCustomUserClaims(record.uid, { packRole: 'active' });
        users.push({
          id: Date.now(), firebaseUid: record.uid,
          username: email.split('@')[0].slice(0, 100), name: name.slice(0, 100), email,
          whatsapp: whatsapp.slice(0, 40), role: 'active'
        });
        const saved = await callAppsScript({ action: 'save_users', users, revision: Number(data.revision || 0) });
        return res.status(200).json({ status: 'success', user: users[users.length - 1], revision: saved.revision });
      } catch (error) {
        if (record) { try { await auth.deleteUser(record.uid); } catch (_) {} }
        throw error;
      }
    }

    const id = String(body.id || (body.user && body.user.id) || '');
    const index = users.findIndex(u => String(u.id) === id);
    if (index < 0 || users[index].role === 'admin' || !users[index].firebaseUid) {
      return res.status(404).json({ status: 'error', message: 'Usuário não encontrado ou ainda não migrado para o Firebase.' });
    }
    const current = users[index];
    const uid = String(current.firebaseUid);

    if (action === 'update') {
      const u = body.user || {};
      const updates = {};
      if (u.email !== undefined) updates.email = String(u.email).trim().toLowerCase();
      if (u.name !== undefined) updates.displayName = String(u.name).trim().slice(0, 100);
      if (u.password) updates.password = String(u.password);
      const nextProfile = {
        ...current,
        name: u.name !== undefined ? String(u.name).trim().slice(0, 100) : current.name,
        email: u.email !== undefined ? String(u.email).trim().toLowerCase() : current.email,
        whatsapp: u.whatsapp !== undefined ? String(u.whatsapp).trim().slice(0, 40) : current.whatsapp
      };
      if (updates.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(updates.email)) {
        return res.status(400).json({ status: 'error', message: 'Informe um e-mail válido.' });
      }
      users[index] = nextProfile;
      await auth.updateUser(uid, updates);
      try {
        const saved = await callAppsScript({ action: 'save_users', users, revision: Number(data.revision || 0) });
        return res.status(200).json({ status: 'success', revision: saved.revision });
      } catch (error) {
        try { await auth.updateUser(uid, { email: current.email, displayName: current.name }); } catch (_) {}
        throw error;
      }
    }

    if (action === 'status') {
      const role = body.role === 'on_hold' ? 'on_hold' : 'active';
      users[index] = { ...current, role };
      // Conta Firebase permanece habilitada: o bloqueio é aplicado pela função do perfil,
      // permitindo que o assinante pausado entre e veja o aviso de suspensão.
      await auth.setCustomUserClaims(uid, { packRole: role });
      try {
        const saved = await callAppsScript({ action: 'save_users', users, revision: Number(data.revision || 0) });
        return res.status(200).json({ status: 'success', revision: saved.revision });
      } catch (error) {
        try { await auth.setCustomUserClaims(uid, { packRole: current.role }); } catch (_) {}
        throw error;
      }
    }

    if (action === 'delete') {
      users.splice(index, 1);
      const saved = await callAppsScript({ action: 'save_users', users, revision: Number(data.revision || 0) });
      try {
        await auth.deleteUser(uid);
      } catch (error) {
        // Restaura o perfil se a exclusão da conta Firebase falhar.
        try { await callAppsScript({ action: 'save_users', users: originalUsers, revision: Number(saved.revision || 0) }); } catch (_) {}
        throw error;
      }
      return res.status(200).json({ status: 'success', revision: saved.revision });
    }

    return res.status(400).json({ status: 'error', message: 'Ação inválida.' });
  } catch (error) {
    return res.status(error.statusCode || 500).json({ status: 'error', message: error.message || 'Erro interno.' });
  }
};
