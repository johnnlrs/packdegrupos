const admin = require('firebase-admin');

function getAdminApp() {
  if (admin.apps.length) return admin.app();
  const raw = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  if (!raw) throw new Error('FIREBASE_SERVICE_ACCOUNT_JSON não configurada na Vercel.');
  let serviceAccount;
  try { serviceAccount = JSON.parse(raw); }
  catch (_) { throw new Error('FIREBASE_SERVICE_ACCOUNT_JSON não contém JSON válido.'); }
  return admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
}

function authAdmin() {
  getAdminApp();
  return admin.auth();
}

async function requireFirebaseUser(req) {
  const header = req.headers.authorization || '';
  const match = header.match(/^Bearer\s+(.+)$/i);
  if (!match) throw Object.assign(new Error('Autenticação necessária.'), { statusCode: 401 });
  try {
    const decoded = await authAdmin().verifyIdToken(match[1], true);
    return decoded;
  } catch (_) {
    throw Object.assign(new Error('Sessão inválida ou expirada. Entre novamente.'), { statusCode: 401 });
  }
}

module.exports = { admin, authAdmin, requireFirebaseUser };
