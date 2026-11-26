const { requirePackProfile } = require('./_lib/authorization');
const { callAppsScript } = require('./_lib/appsScript');

module.exports = async function handler(req, res) {
  try {
    if (req.method === 'GET') {
      // Visitantes recebem somente a estrutura pública dos blocos, nunca links ou perfis.
      const authorization = req.headers.authorization || '';
      if (!/^Bearer\s+.+$/i.test(authorization)) {
        const data = await callAppsScript({ action: 'get_data' });
        return res.status(200).json({
          status: 'success', hasData: data.hasData, revision: data.revision,
          blocks: data.blocks || [], links: {}, linkCounts: buildLinkCounts(data.links || {}), users: []
        });
      }
      const { profile, data } = await requirePackProfile(req, ['admin', 'active', 'on_hold']);
      if (profile.role === 'on_hold') {
        return res.status(200).json({ status: 'success', hasData: true, revision: data.revision, user: safeProfile(profile), blocks: [], links: {}, users: [] });
      }
      if (profile.cpfRequired && !profile.cpfVerifiedAt && profile.role !== 'admin') {
        return res.status(200).json({ status: 'success', hasData: true, revision: data.revision, user: safeProfile(profile), blocks: [], links: {}, users: [] });
      }
      return res.status(200).json({
        status: 'success', hasData: data.hasData, revision: data.revision,
        user: safeProfile(profile),
        users: profile.role === 'admin' ? (data.users || []).map(safeProfile) : [],
        blocks: data.blocks || [], links: data.links || {}
      });
    }
    if (req.method === 'POST') {
      await requirePackProfile(req, ['admin']);
      const body = typeof req.body === 'string' ? JSON.parse(req.body) : (req.body || {});
      if (body.action !== 'save_all') return res.status(400).json({ status: 'error', message: 'Ação inválida.' });
      const result = await callAppsScript({ action: 'save_all', revision: Number(body.revision || 0), blocks: body.blocks, links: body.links });
      return res.status(200).json(result);
    }
    res.setHeader('Allow', 'GET, POST');
    return res.status(405).json({ status: 'error', message: 'Método não permitido.' });
  } catch (error) {
    return res.status(error.statusCode || 500).json({ status: 'error', message: error.message || 'Erro interno.' });
  }
};

function buildLinkCounts(links) {
  const counts = {};
  for (const [blockId, block] of Object.entries(links || {})) {
    const stateCount = Array.isArray(block?.stateItems)
      ? block.stateItems.filter(item => item && item.type === 'link').length : 0;
    const cityCount = Array.isArray(block?.cities)
      ? block.cities.reduce((total, city) => total + (Array.isArray(city?.items)
        ? city.items.filter(item => item && item.type === 'link').length : 0), 0) : 0;
    counts[blockId] = stateCount + cityCount;
  }
  return counts;
}

function safeProfile(user) {
  const { password, cpfHash, ...safe } = user || {};
  safe.cpfRequired = !!(user && user.cpfRequired && !user.cpfVerifiedAt);
  return safe;
}
