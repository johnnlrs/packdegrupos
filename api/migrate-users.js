// Execute uma única vez após configurar os segredos. Depois, remova MIGRATION_SECRET
// da Vercel e exclua este endpoint do deploy.
const { authAdmin } = require('./_lib/firebaseAdmin');
const { callAppsScript } = require('./_lib/appsScript');

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ status: 'error', message: 'Método não permitido.' });
  const expected = process.env.MIGRATION_SECRET;
  const supplied = req.headers['x-migration-secret'];
  if (!expected || !supplied || supplied !== expected) return res.status(404).json({ status: 'error', message: 'Não encontrado.' });

  try {
    const auth = authAdmin();
    const data = await callAppsScript({ action: 'get_data' });
    const users = Array.isArray(data.users) ? data.users : [];
    const migrated = [];
    const skipped = [];
    const cleaned = [];
    const emailFrequency = new Map();
    for (const item of users) {
      const normalized = String(item.email || '').trim().toLowerCase();
      if (normalized) emailFrequency.set(normalized, (emailFrequency.get(normalized) || 0) + 1);
    }

    for (const source of users) {
      const user = { ...source };
      const email = String(user.email || '').trim().toLowerCase();
      const password = String(user.password || '');
      if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        skipped.push({ id: user.id, reason: 'E-mail ausente ou inválido; atualizar cadastro antes da migração.' });
        cleaned.push(user);
        continue;
      }
      if ((emailFrequency.get(email) || 0) > 1) {
        skipped.push({ id: user.id, reason: 'E-mail duplicado em mais de um perfil; corrigir antes da migração.' });
        cleaned.push(user);
        continue;
      }
      if (!password && !user.firebaseUid) {
        skipped.push({ id: user.id, reason: 'Senha antiga ausente; será necessário redefinir a senha.' });
        cleaned.push(user);
        continue;
      }

      let record;
      try {
        if (user.firebaseUid) {
          record = await auth.getUser(String(user.firebaseUid));
        } else {
          try { record = await auth.getUserByEmail(email); }
          catch (e) {
            if (e.code !== 'auth/user-not-found') throw e;
            record = await auth.createUser({ email, password, displayName: String(user.name || user.username || email).slice(0, 100), disabled: user.role === 'on_hold' });
          }
        }
        const role = ['admin', 'active', 'on_hold'].includes(user.role) ? user.role : 'on_hold';
        // Não desabilitar contas pausadas no Firebase: o site precisa autenticar
        // o usuário para exibir o aviso de assinatura suspensa.
        await auth.updateUser(record.uid, { disabled: false });
        await auth.setCustomUserClaims(record.uid, { packRole: role });
        user.firebaseUid = record.uid;
        delete user.password;
        cleaned.push(user);
        migrated.push({ id: user.id, role });
      } catch (e) {
        skipped.push({ id: user.id, reason: e.code || 'Falha ao criar/associar conta Firebase.' });
        cleaned.push(user);
      }
    }

    const saved = await callAppsScript({ action: 'save_users', users: cleaned, revision: Number(data.revision || 0) });
    return res.status(200).json({ status: 'success', migrated, skipped, revision: saved.revision, note: 'Remova MIGRATION_SECRET e este endpoint após conferir o relatório.' });
  } catch (error) {
    return res.status(500).json({ status: 'error', message: error.message || 'Falha na migração.' });
  }
};
