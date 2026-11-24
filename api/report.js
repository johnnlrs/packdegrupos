const { requirePackProfile } = require('./_lib/authorization');
const { callAppsScript } = require('./_lib/appsScript');

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ status: 'error', message: 'Método não permitido.' });
  }
  try {
    const { profile } = await requirePackProfile(req, ['admin', 'active']);
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : (req.body || {});
    const required = ['name', 'email', 'state', 'city'];
    if (required.some(k => !String(body[k] || '').trim())) return res.status(400).json({ status: 'error', message: 'Preencha os campos obrigatórios.' });
    const result = await callAppsScript({
      action: 'save_report', name: String(body.name).slice(0,120), email: String(body.email).slice(0,180),
      state: String(body.state).slice(0,100), city: String(body.city).slice(0,100),
      nicho: String(body.nicho || '').slice(0,120), desc: String(body.desc || '').slice(0,2000),
      submittedBy: String(profile.name || profile.username || profile.email || '').slice(0,180)
    });
    return res.status(200).json(result);
  } catch (error) {
    return res.status(error.statusCode || 500).json({ status: 'error', message: error.message || 'Erro interno.' });
  }
};
