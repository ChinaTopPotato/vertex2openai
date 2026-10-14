"""Small addition to the existing console, with no separate frontend build."""

CARD = r'''
    <div class="card p-5 mb-4" id="proxy-pool-card">
      <div class="flex items-center justify-between gap-3 mb-3">
        <div>
          <div class="text-sm font-semibold">订阅代理池</div>
          <div class="text-xs text-neutral-500 mt-1">每个新模型请求轮换节点，优先交错不同出口网段</div>
        </div>
        <label class="flex items-center gap-2 text-sm shrink-0"><input id="proxy-pool-enabled" type="checkbox">启用</label>
      </div>
      <label class="lbl mb-2 block" for="proxy-pool-url">HTTPS 订阅链接</label>
      <input id="proxy-pool-url" type="password" autocomplete="new-password" class="inp mb-3" placeholder="粘贴 VLESS / Base64 订阅；已配置时留空可保留">
      <label class="lbl mb-2 block" for="proxy-pool-filter">节点名称筛选（可选）</label>
      <input id="proxy-pool-filter" class="inp mb-3" placeholder="例如：日本,新加坡,美国；留空使用全部节点">
      <div class="flex flex-wrap items-center gap-2 mb-3">
        <button id="proxy-pool-save" type="button" class="btn px-4 py-2 text-sm" onclick="saveProxyPool(false)">保存设置</button>
        <button id="proxy-pool-refresh" type="button" class="px-4 py-2 text-sm border border-neutral-300 rounded-lg" onclick="saveProxyPool(true)">更新订阅并检测</button>
        <button id="proxy-pool-test" type="button" class="px-4 py-2 text-sm border border-neutral-300 rounded-lg" onclick="testNextProxy()">测试下一出口</button>
        <span id="proxy-pool-status" class="text-sm text-neutral-500" role="status" aria-live="polite">正在读取配置…</span>
      </div>
      <p class="text-xs text-neutral-500 leading-relaxed">Express 与 Cookie 通道均生效。服务器检测并按出口 IP 去重，轮换时交错不同出口网段。仅手动更新时检测；当前流式回复继续使用原节点，上游 429 保留退避重试。Cloudflare 出口可能变化，不能保证每次实际 IP 都不重复。</p>
      <p id="proxy-pool-error" class="text-sm text-rose-600 mt-2" role="alert"></p>
      <p id="proxy-pool-last" class="text-xs text-neutral-500 mt-2"></p>
      <details class="mt-3">
        <summary class="text-sm cursor-pointer">查看已检测出口</summary>
        <div class="overflow-auto max-h-64 mt-2">
          <table class="w-full text-xs text-left"><thead><tr><th class="p-2">节点</th><th class="p-2">检测出口 IP</th><th class="p-2">检测耗时</th></tr></thead><tbody id="proxy-pool-nodes"></tbody></table>
        </div>
      </details>
    </div>
'''

SCRIPT = r'''
/* ---------- Subscription proxy pool ---------- */
let proxyPoolPoll = null;
function renderProxyPool(s, fill) {
  if (fill) {
    $('proxy-pool-enabled').checked = !!s.enabled;
    $('proxy-pool-filter').value = s.name_filter || '';
    $('proxy-pool-url').placeholder = s.subscription_configured
      ? '已保存订阅链接；留空保留，粘贴新链接可替换'
      : '粘贴 VLESS / Base64 订阅链接';
  }
  const job = s.job || {};
  const busy = ['downloading','checking'].includes(job.state);
  $('proxy-pool-save').disabled = busy;
  $('proxy-pool-refresh').disabled = busy;
  $('proxy-pool-test').disabled = !s.enabled || !s.ready;
  $('proxy-pool-status').textContent = busy
    ? (job.state === 'downloading' ? '正在下载订阅…' : `正在检测 ${job.checked}/${job.total}，已通过 ${job.passed}`)
    : (s.enabled ? (s.ready ? `已启用 · ${s.node_count} 条已检测线路 · ${s.exit_network_count} 个出口网段` : '已启用，出口尚不可用') : '已关闭');
  $('proxy-pool-error').textContent = s.last_error || '';
  const last = s.last_selected;
  $('proxy-pool-last').textContent = [
    s.last_updated ? '上次更新：' + new Date(s.last_updated*1000).toLocaleString() : '',
    last ? `最近选用：${last.name} · ${last.exit_ip}` : '',
    s.imported_count ? `订阅解析 ${s.imported_count} 条` : ''
  ].filter(Boolean).join(' ｜ ');
  const rows = $('proxy-pool-nodes'); rows.replaceChildren();
  (s.nodes || []).forEach(n => {
    const row = document.createElement('tr');
    [n.name, n.exit_ip || '—', (n.latency_ms || 0) + ' ms'].forEach(value => {
      const cell = document.createElement('td'); cell.className='p-2 border-t border-neutral-100';
      cell.textContent=value; row.appendChild(cell);
    }); rows.appendChild(row);
  });
  clearTimeout(proxyPoolPoll);
  if (busy) proxyPoolPoll = setTimeout(() => loadProxyPool(false), 2000);
}
async function loadProxyPool(fill=true) {
  try {
    const r = await fetch('/api/proxy-pool');
    if (!r.ok) throw new Error('读取代理池状态失败，请重新登录后重试。');
    renderProxyPool(await r.json(), fill);
  } catch(e) { $('proxy-pool-error').textContent=e.message; }
}
async function saveProxyPool(refresh) {
  $('proxy-pool-save').disabled = true; $('proxy-pool-refresh').disabled = true;
  $('proxy-pool-error').textContent = '';
  try {
    const r=await fetch('/api/proxy-pool',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({
      enabled:$('proxy-pool-enabled').checked,
      subscription_url:$('proxy-pool-url').value.trim(),
      name_filter:$('proxy-pool-filter').value.trim(), refresh:refresh
    })});
    const s=await r.json();
    if (!r.ok) throw new Error(s.error || '保存代理池失败。');
    $('proxy-pool-url').value=''; renderProxyPool(s, false);
  } catch(e) {
    $('proxy-pool-error').textContent=e.message;
    $('proxy-pool-save').disabled=false; $('proxy-pool-refresh').disabled=false;
  }
}
async function testNextProxy() {
  $('proxy-pool-test').disabled=true;
  $('proxy-pool-error').textContent='';
  $('proxy-pool-status').textContent='正在测试下一出口…';
  try {
    const r=await fetch('/api/proxy-pool/check-next',{method:'POST'});
    const s=await r.json();
    if(!r.ok) throw new Error(typeof s.error==='string' ? s.error : (s.error?.message || '出口测试失败。'));
    await loadProxyPool(false);
    $('proxy-pool-status').textContent=`测试通过 · ${s.node} · 实际出口 ${s.observed_exit_ip}`;
  } catch(e) { await loadProxyPool(false); $('proxy-pool-error').textContent=e.message; }
  finally { $('proxy-pool-test').disabled=false; }
}
loadProxyPool();
'''


def install_proxy_pool_ui(html):
    marker = '    <!-- Express API Key 列表（多账号，热编辑） -->'
    if marker not in html or '/* init */' not in html:
        raise RuntimeError("控制台结构已变更，代理池界面需要重新适配。")
    return html.replace(marker, CARD + '\n' + marker, 1).replace('/* init */', SCRIPT + '\n/* init */', 1)
