
const crypto = require('crypto');
const { authAdmin } = require('./_lib/firebaseAdmin');
const { callAppsScript } = require('./_lib/appsScript');

const CONFIRMATION = 'MIGRAR_USUARIOS_ANTIGOS';
const VALID_ROLES = new Set(['admin', 'active', 'on_hold']);

function send(res, statusCode, payload) {
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  res.setHeader('Pragma', 'no-cache');
  return res.status(statusCode).json(payload);
}

function secretMatches(expected, supplied) {
  if (
    typeof expected !== 'string' ||
    typeof supplied !== 'string' ||
    !expected ||
    !supplied
  ) return false;

  const a = Buffer.from(expected, 'utf8');
  const b = Buffer.from(supplied, 'utf8');

  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function validEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function safeId(user, index) {
  return user &&
    user.id !== undefined &&
    user.id !== null &&
    String(user.id) !== ''
    ? String(user.id)
    : `linha_${index + 1}`;
}

function isUserNotFound(error) {
  return error && error.code === 'auth/user-not-found';
}

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return send(res, 405, {
      status: 'error',
      message: 'Método não permitido.'
    });
  }

  if (!secretMatches(
    process.env.MIGRATION_SECRET,
    req.headers['x-migration-secret']
  )) {
    return send(res, 404, {
      status: 'error',
      message: 'Não encontrado.'
    });
  }

  let body = req.body;

  if (typeof body === 'string') {
    try {
      body = JSON.parse(body);
    } catch (_) {
      return send(res, 400, {
        status: 'error',
        message: 'Corpo JSON inválido.'
      });
    }
  }

  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    body = {};
  }

  const mode = body.mode === 'execute' ? 'execute' : 'preview';

  if (mode === 'execute' && body.confirm !== CONFIRMATION) {
    return send(res, 400, {
      status: 'error',
      message: 'Confirmação ausente ou inválida. Nenhuma migração foi executada.'
    });
  }

  try {
    const auth = authAdmin();
    const data = await callAppsScript({ action: 'get_data' });
    const users = Array.isArray(data.users) ? data.users : [];

    const emailCounts = new Map();
    const uidCounts = new Map();

    users.forEach((user) => {
      const email = normalizeEmail(user && user.email);
      const uid = String((user && user.firebaseUid) || '').trim();

      if (email) {
        emailCounts.set(email, (emailCounts.get(email) || 0) + 1);
      }

      if (uid) {
        uidCounts.set(uid, (uidCounts.get(uid) || 0) + 1);
      }
    });

    const report = [];
    const changes = [];
    const finalUsers = users.map((user) => ({ ...(user || {}) }));

    for (let index = 0; index < users.length; index++) {
      const user = users[index] || {};
      const id = safeId(user, index);
      const email = normalizeEmail(user.email);
      const uid = String(user.firebaseUid || '').trim();
      const password = String(user.password || '');
      const role = String(user.role || '').trim();

      const item = {
        index,
        id,
        email,
        uid,
        password,
        role,
        action: null,
        record: null
      };

      let reason = '';

      if (!validEmail(email)) {
        reason = 'E-mail ausente ou inválido.';
      } else if ((emailCounts.get(email) || 0) > 1) {
        reason = 'E-mail duplicado em mais de um cadastro.';
      } else if (uid && (uidCounts.get(uid) || 0) > 1) {
        reason = 'UID duplicado em mais de um cadastro.';
      } else if (!VALID_ROLES.has(role)) {
        reason = 'Função/role não reconhecida; cadastro preservado para revisão.';
      }

      if (!reason && uid) {
        try {
          const record = await auth.getUser(uid);

          if (normalizeEmail(record.email) !== email) {
            reason = 'O e-mail do cadastro não corresponde ao e-mail da conta Firebase vinculada.';
          } else {
            item.record = record;
            item.action = 'manter_vinculo_existente';
          }
        } catch (error) {
          reason = isUserNotFound(error)
            ? 'UID informado no cadastro não existe no Firebase.'
            : `Não foi possível consultar o UID no Firebase (${error.code || 'erro'}).`;
        }
      } else if (!reason) {
        if (password.length < 6) {
          reason = 'Senha antiga ausente ou menor que 6 caracteres; redefinição necessária.';
        } else {
          try {
            item.record = await auth.getUserByEmail(email);
            item.action = 'vincular_conta_existente_e_sincronizar_senha';
          } catch (error) {
            if (isUserNotFound(error)) {
              item.action = 'criar_conta_firebase';
            } else {
              reason = `Não foi possível consultar o e-mail no Firebase (${error.code || 'erro'}).`;
            }
          }
        }
      }

      if (reason) {
        report.push({
          index,
          id,
          email: email || null,
          status: 'ignorado',
          reason
        });
      } else {
        changes.push(item);

        report.push({
          index,
          id,
          email,
          status: 'apto',
          action: item.action
        });
      }
    }

    if (mode === 'preview') {
      return send(res, 200, {
        status: 'preview',
        mode: 'preview',
        message: 'Prévia concluída. Nenhuma conta Firebase ou dado da planilha foi alterado.',
        revision: Number(data.revision || 0),
        total: users.length,
        aptos: changes.length,
        ignorados: report.length - changes.length,
        planned: report
      });
    }

    const unsafeLinkedSkips = report.filter((item) => {
      if (item.status !== 'ignorado') return false;

      const original = users[item.index] || {};

      return !!(
        original &&
        original.firebaseUid &&
        original.password
      );
    });

    if (unsafeLinkedSkips.length) {
      return send(res, 409, {
        status: 'blocked',
        mode: 'execute',
        message: 'Execução bloqueada antes de alterar o Firebase. Há perfil com firebaseUid e senha antiga que foi ignorado; é necessário revisar esse cadastro primeiro.',
        blocked: unsafeLinkedSkips
      });
    }

    const migrated = [];
    const failed = [];

    for (const item of changes) {
      try {
        let record = item.record;

        if (item.action === 'criar_conta_firebase') {
          record = await auth.createUser({
            email: item.email,
            password: item.password,
            displayName: String(
              users[item.index].name ||
              users[item.index].username ||
              item.email
            ).slice(0, 100),
            disabled: false
          });

        } else if (
          item.action === 'vincular_conta_existente_e_sincronizar_senha'
        ) {
          await auth.updateUser(record.uid, {
            password: item.password,
            disabled: false
          });

          record = await auth.getUser(record.uid);

        } else {
          await auth.updateUser(record.uid, {
            disabled: false
          });
        }

        const existingClaims = record.customClaims || {};

        await auth.setCustomUserClaims(record.uid, {
          ...existingClaims,
          packRole: item.role
        });

        finalUsers[item.index].firebaseUid = record.uid;
        delete finalUsers[item.index].password;

        migrated.push({
          id: item.id,
          email: item.email,
          role: item.role,
          action: item.action
        });

      } catch (error) {
        failed.push({
          index: item.index,
          id: item.id,
          email: item.email,
          reason: error.code ||
            'Falha ao criar ou atualizar a conta Firebase.'
        });
      }
    }

    if (migrated.length === 0) {
      return send(res, 200, {
        status: 'completed',
        mode: 'execute',
        message: 'Nenhum perfil foi migrado; a planilha não foi gravada.',
        migrated,
        failed,
        skipped: report.filter(
          (item) => item.status === 'ignorado'
        ),
        revision: Number(data.revision || 0)
      });
    }

    const failedLinkedWithPassword = failed.filter((item) => {
      const original = users[item.index] || {};

      return !!(
        original.firebaseUid &&
        original.password
      );
    });

    if (failedLinkedWithPassword.length) {
      return send(res, 409, {
        status: 'partial_blocked',
        mode: 'execute',
        message: 'Algumas operações Firebase falharam em perfis vinculados que ainda possuem senha antiga. A planilha não foi gravada para evitar que save_users apague essas senhas. Interrompa e revise o relatório.',
        migrated,
        failed: failedLinkedWithPassword,
        warning: 'Algumas contas Firebase podem já ter sido atualizadas. Não repita a execução sem revisar o estado atual.'
      });
    }

    const saved = await callAppsScript({
      action: 'save_users',
      users: finalUsers,
      revision: Number(data.revision || 0)
    });

    return send(res, 200, {
      status: 'completed',
      mode: 'execute',
      message: 'Migração processada. Confira os resultados antes de remover o endpoint e o segredo temporário.',
      migrated,
      failed,
      skipped: report.filter(
        (item) => item.status === 'ignorado'
      ),
      revision: saved.revision,
      warning: 'As alterações no Firebase ocorrem antes da gravação na planilha. Se houver conflito de revisão ou falha na gravação, algumas contas podem ter sido atualizadas no Firebase sem o vínculo correspondente na planilha; nesse caso, interrompa e revise antes de tentar novamente.'
    });

  } catch (error) {
    const status = error && error.statusCode === 409
      ? 409
      : 500;

    return send(res, status, {
      status: 'error',
      message: error.message || 'Falha ao processar a migração.'
    });
  }
};
