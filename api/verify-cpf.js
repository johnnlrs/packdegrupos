const crypto = require('crypto');
const { requirePackProfile } = require('./_lib/authorization');
const { callAppsScript } = require('./_lib/appsScript');

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ status: 'error', message: 'Método não permitido.' });
  }

  try {
    const { profile, data } = await requirePackProfile(req, ['active']);
    if (!profile.cpfRequired) {
      return res.status(409).json({ status: 'error', message: 'Este cadastro não exige verificação de CPF.' });
    }
    if (profile.cpfVerifiedAt) {
      return res.status(200).json({ status: 'success', verified: true });
    }

    const body = typeof req.body === 'string' ? JSON.parse(req.body) : (req.body || {});
    const cpf = String(body.cpf || '').replace(/\D/g, '');
    if (body.accepted !== true) {
      return res.status(400).json({ status: 'error', message: 'Confirme a leitura do aviso de privacidade para continuar.' });
    }
    if (!isValidCpf(cpf)) {
      return res.status(400).json({ status: 'error', message: 'CPF inválido. Confira os 11 números digitados.' });
    }

    // Chave dedicada recomendada; fallback mantém compatibilidade com a configuração atual da Vercel.
    const secret = process.env.CPF_HASH_SECRET || process.env.PACK_BACKEND_SECRET;
    if (!secret) {
      return res.status(500).json({ status: 'error', message: 'A proteção de CPF não está configurada no servidor.' });
    }
    const cpfHash = crypto.createHmac('sha256', secret).update('packdegrupos:cpf:v1:' + cpf).digest('hex');
    const users = Array.isArray(data.users) ? data.users : [];
    const duplicate = users.find(user => {
      const storedHash = String(user.cpfHash || '');
      return String(user.firebaseUid || '') !== String(profile.firebaseUid || '') &&
        storedHash.length === cpfHash.length &&
        crypto.timingSafeEqual(Buffer.from(storedHash), Buffer.from(cpfHash));
    });
    if (duplicate) {
      return res.status(409).json({ status: 'error', message: 'Este CPF já está associado a outro cadastro da plataforma. Entre em contato com o administrador.' });
    }

    const updatedUsers = users.map(user => {
      if (String(user.firebaseUid || '') !== String(profile.firebaseUid || '')) return user;
      return {
        ...user,
        cpfHash,
        cpfVerifiedAt: new Date().toISOString(),
        cpfNoticeAcceptedAt: new Date().toISOString(),
        cpfNoticeVersion: '2026-11-26-v1'
      };
    });
    const saved = await callAppsScript({
      action: 'save_users',
      users: updatedUsers,
      revision: Number(data.revision || 0)
    });
    return res.status(200).json({ status: 'success', verified: true, revision: saved.revision });
  } catch (error) {
    return res.status(error.statusCode || 500).json({ status: 'error', message: error.message || 'Não foi possível concluir a verificação.' });
  }
};

function isValidCpf(cpf) {
  if (!/^\\d{11}$/.test(cpf) || /^(\\d)\\1{10}$/.test(cpf)) return false;
  const digits = cpf.split('').map(Number);
  for (let position = 9; position < 11; position++) {
    let sum = 0;
    for (let i = 0; i < position; i++) sum += digits[i] * ((position + 1) - i);
    const remainder = (sum * 10) % 11;
    const check = remainder === 10 ? 0 : remainder;
    if (check !== digits[position]) return false;
  }
  return true;
}
