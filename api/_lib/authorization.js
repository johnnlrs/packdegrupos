const { requireFirebaseUser } = require('./firebaseAdmin');
const { callAppsScript } = require('./appsScript');

async function requirePackProfile(req, allowedRoles) {
  const identity = await requireFirebaseUser(req);
  const data = await callAppsScript({ action: 'get_data' });
  const users = Array.isArray(data.users) ? data.users : [];
  const profile = users.find(u => String(u.firebaseUid || '') === String(identity.uid));
  if (!profile || !allowedRoles.includes(String(profile.role || ''))) {
    throw Object.assign(new Error('Sua conta não tem permissão para esta operação.'), { statusCode: 403 });
  }
  return { identity, profile, data };
}

module.exports = { requirePackProfile };
