async function callAppsScript(payload) {
  const url = process.env.APPS_SCRIPT_URL;
  const secret = process.env.PACK_BACKEND_SECRET;
  if (!url || !secret) throw new Error('APPS_SCRIPT_URL e PACK_BACKEND_SECRET devem estar configuradas na Vercel.');
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'text/plain;charset=utf-8' },
    body: JSON.stringify({ ...payload, serverSecret: secret })
  });
  if (!response.ok) throw new Error(`Apps Script respondeu HTTP ${response.status}.`);
  const result = await response.json();
  if (!result || result.status !== 'success') throw new Error(result?.message || 'Falha no serviço de dados.');
  return result;
}

module.exports = { callAppsScript };
