const crypto = require('crypto');
const { requirePackProfile } = require('./_lib/authorization');
const { callAppsScript } = require('./_lib/appsScript');

module.exports = async function handler(req, res) {
  if (req.method !== 'POST' && req.method !== 'GET') {
    res.setHeader('Allow', 'GET, POST');
    return res.status(405).json({ status: 'error', message: 'Método não permitido.' });
  }

  try {
    const { profile, data } = await requirePackProfile(req, ['active']);
    if (req.method === 'GET') {
      if (!profile.cpfVerifiedAt || !profile.cpfEncrypted) {
        return res.status(404).json({ status: 'error', message: 'CPF completo não disponível neste cadastro.' });
      }
      const key = deriveEncryptionKey(getSecret());
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(profile.cpfEncrypted.iv, 'hex'));
      decipher.setAuthTag(Buffer.from(profile.cpfEncrypted.tag, 'hex'));
      const plaintext = Buffer.concat([
        decipher.update(Buffer.from(profile.cpfEncrypted.ciphertext, 'hex')),
        decipher.final()
      ]).toString('utf8');
      return res.status(200).json({ status: 'success', cpf: plaintext });
    }
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

    const secret = getSecret();
    const cpfHash = crypto.createHmac('sha256', secret).update('packdegrupos:cpf:v1:' + cpf).digest('hex');
    const encryptionKey = deriveEncryptionKey(secret);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv);
    const ciphertext = Buffer.concat([cipher.update(cpf, 'utf8'), cipher.final()]);
    const cpfEncrypted = {
      iv: iv.toString('hex'),
      tag: cipher.getAuthTag().toString('hex'),
      ciphertext: ciphertext.toString('hex')
    };
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
        cpfEncrypted,
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

function getSecret() {
  const secret = process.env.CPF_HASH_SECRET;
  if (!secret || secret.length < 32) {
    const error = new Error('A proteção de CPF ainda não foi configurada pelo administrador.');
    error.statusCode = 500;
    throw error;
  }
  return secret;
}

function deriveEncryptionKey(secret) {
  return crypto.createHash('sha256').update('packdegrupos:cpf-encryption:v1:' + secret).digest();
}

function isValidCpf(cpf) {
  if (!/^\d{11}$/.test(cpf) || /^(\d)\1{10}$/.test(cpf)) return false;
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
