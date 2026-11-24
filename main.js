// SPDX-License-Identifier: MIT
(async function () {
  'use strict';
  const db = window.__KM_PLUGIN_API__.database;
  const iterations = 600000;
  const idleMs = 5 * 60 * 1000;
  const encoder = new TextEncoder();
  const decoder = new TextDecoder('utf-8', { fatal: true });
  let session = null;
  let epoch = 0;
  let busy = false;
  let idleTimer;
  let snapshot;
  const style = document.createElement('style');
  style.textContent = `
    *{box-sizing:border-box}body{margin:0;background:#f6f7f4;color:#20332e;font:15px/1.5 system-ui,sans-serif}
    main{max-width:950px;margin:auto;padding:clamp(18px,4vw,42px)}h1,h2,p{margin:0 0 14px}
    h1{font-size:27px}h2{font-size:18px}.card,article{background:white;border:1px solid #d6dfd9;border-radius:12px;padding:18px;margin:10px 0}
    .narrow{max-width:490px;margin:7vh auto}.row{display:flex;gap:9px;align-items:center;flex-wrap:wrap}.bar{justify-content:space-between}
    label{display:block;font-weight:600;margin:10px 0}input,textarea{width:100%;padding:10px;border:1px solid #98aaa1;border-radius:7px;font:inherit;background:white;color:inherit}
    textarea{min-height:80px}button{border:1px solid #aebdb6;border-radius:7px;padding:8px 14px;background:#fff;color:inherit;font:inherit;cursor:pointer}
    button.primary{background:#215f4c;color:white;border-color:#215f4c}button.danger{color:#9d3427}
    button:focus-visible,input:focus-visible,textarea:focus-visible{outline:3px solid #64a993}button:disabled{opacity:.6}
    small,.muted{color:#50645b}article strong,article span{overflow-wrap:anywhere;display:block}
    #notice{min-height:1.5em;color:#884326;margin-top:12px}fieldset{border:0;padding:0;margin:0;min-width:0}
  `;
  document.head.append(style);
  document.body.innerHTML = '<main><fieldset id="view"></fieldset><p id="notice" role="status" aria-live="polite"></p></main>';
  const view = document.querySelector('#view');
  const notice = document.querySelector('#notice');
  const el = id => document.getElementById(id);
  const click = (id, callback) => { el(id).onclick = callback; };
  const formAction = callback => {
    const form = view.querySelector('form');
    const submit = form.querySelector('button.primary');
    // The host deliberately omits allow-forms. Validate locally and use only the SDK.
    submit.type = 'button';
    submit.onclick = () => { if (form.reportValidity()) void run(callback); };
    form.onkeydown = event => {
      if (event.key === 'Enter' && !event.isComposing && event.target.tagName === 'INPUT') {
        event.preventDefault();
        submit.click();
      }
    };
  };
  function page(markup) {
    view.innerHTML = markup; // Only fixed templates. User fields are assigned with value/textContent.
    notice.textContent = '';
  }
  function touch() {
    clearTimeout(idleTimer);
    if (session || view.querySelector('input[type=password]')) idleTimer = setTimeout(lock, idleMs);
  }
  function lock() {
    epoch++;
    session = null;
    clearTimeout(idleTimer);
    page('<section class="card narrow"><h1>密码库已锁定</h1><button id="again" class="primary">打开密码库</button></section>');
    click('again', () => run(load));
  }
  window.addEventListener('message', e => {
    if (e.source === parent && e.data?.__kmPluginPanelClosed) lock();
  });
  document.addEventListener('visibilitychange', () => { if (document.hidden) lock(); });
  for (const event of ['pointerdown', 'keydown', 'input']) document.addEventListener(event, touch);
  async function run(callback) {
    if (busy) return;
    const ticket = epoch;
    busy = true;
    view.disabled = true;
    notice.textContent = '';
    try { await callback(ticket); }
    catch (error) { if (ticket === epoch) notice.textContent = error.message || String(error); }
    finally { busy = false; view.disabled = false; }
  }
  function check(ticket) {
    if (ticket !== epoch) throw new Error('密码库已锁定');
  }
  function base64(bytes) {
    let binary = '';
    for (let i = 0; i < bytes.length; i += 8192)
      binary += String.fromCharCode(...bytes.subarray(i, i + 8192));
    return btoa(binary);
  }
  const decode = value => Uint8Array.from(atob(value), c => c.charCodeAt(0));
  async function derive(password, salt) {
    const material = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, material,
      { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }
  const additionalData = encoder.encode('KyMind password vault v1');
  async function seal(entries, key, salt) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData }, key, encoder.encode(JSON.stringify(entries)));
    return JSON.stringify({ format: 'km-password-vault', version: 1, salt: base64(salt), iv: base64(iv), data: base64(new Uint8Array(ciphertext)) });
  }
  async function decrypt(raw, password) {
    try {
      if (typeof raw !== 'string' || raw.length > 4194304) throw new Error();
      const box = JSON.parse(raw);
      if (box.format !== 'km-password-vault' || box.version !== 1) throw new Error();
      const salt = decode(box.salt), iv = decode(box.iv);
      if (salt.length !== 16 || iv.length !== 12) throw new Error();
      const key = await derive(password, salt);
      const bytes = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData }, key, decode(box.data));
      const entries = JSON.parse(decoder.decode(bytes));
      if (!Array.isArray(entries) || !entries.every(e => e && ['id','site','account','password','notes'].every(k => typeof e[k] === 'string')) ||
          new Set(entries.map(e => e.id)).size !== entries.length) throw new Error();
      return { entries, key, salt };
    } catch { throw new Error('主密码不正确，或加密数据已损坏。'); }
  }
  async function save(ticket, next) {
    const value = await seal(next.entries, next.key, next.salt);
    check(ticket);
    const revision = await db.commit(snapshot.revision, value);
    check(ticket);
    snapshot = { revision, value };
    session = next;
    list();
    touch();
  }
  async function load(ticket) {
    if (!crypto.subtle) throw new Error('当前宿主缺少 Web Crypto，请使用 KyMind 桌面版。');
    let read;
    try { read = await db.read(); }
    catch (error) {
      if (/未知 API 域|read_plugin_database.*not found/i.test(String(error)))
        throw new Error('请先运行支持插件独立数据库的新版 KyMind，再打开密码库。');
      throw error;
    }
    check(ticket);
    if (!read || !Number.isSafeInteger(read.revision) ||
        !(read.revision === 0 && read.value === null || read.revision > 0 && typeof read.value === 'string'))
      throw new Error('密码库读取异常，请检查宿主版本后重试。');
    snapshot = read;
    const create = snapshot.revision === 0;
    page(`<section class="card narrow"><h1>${create ? '创建本机密码库' : '解锁密码库'}</h1>
      <p class="muted">${create ? '设置至少 12 个字符的主密码。请妥善保管，遗忘后无法恢复。' : '输入主密码以查看本机保存的账号。'}</p>
      <form><label>主密码<input id="master" type="password" required autocomplete="off"></label>
      ${create ? '<label>确认主密码<input id="confirm" type="password" required autocomplete="off"></label>' : ''}
      <div class="row"><button class="primary">${create ? '创建密码库' : '解锁'}</button>
      ${create ? '<button type="button" id="restore">恢复加密备份</button>' : ''}</div></form></section>`);
    if (create) click('restore', restore);
    formAction(async ticket => {
      const password = el('master').value;
      if (create) {
        validateNew(password, el('confirm').value);
        const salt = crypto.getRandomValues(new Uint8Array(16));
        await save(ticket, { entries: [], salt, key: await derive(password, salt) });
      } else {
        const unlocked = await decrypt(snapshot.value, password);
        check(ticket); session = unlocked; list(); touch();
      }
    });
    touch();
  }
  function validateNew(password, confirmation) {
    if (Array.from(password).length < 12) throw new Error('主密码至少需要 12 个字符。');
    if (password !== confirmation) throw new Error('两次输入的主密码不一致。');
  }
  function list() {
    page(`<header class="row bar"><h1>账号密码</h1><div class="row">
      <button id="backup">加密备份</button><button id="change">修改主密码</button><button id="lock">锁定</button></div></header>
      <div class="card"><label>搜索网站、账号或备注<input id="search" type="search"></label>
      <button id="add" class="primary">新增账号</button></div><section id="items"></section>`);
    click('lock', lock); click('backup', backup); click('change', change); click('add', () => edit(null));
    function render() {
      const q = el('search').value.trim().toLowerCase();
      const items = el('items'); items.replaceChildren();
      for (const entry of session.entries) {
        if (![entry.site, entry.account, entry.notes].some(text => text.toLowerCase().includes(q))) continue;
        const row = document.createElement('article');
        row.className = 'row bar';
        row.innerHTML = '<div><strong></strong><span></span></div><button>查看 / 编辑</button>';
        row.querySelector('strong').textContent = entry.site;
        row.querySelector('span').textContent = entry.account;
        row.querySelector('button').onclick = () => edit(entry);
        items.append(row);
      }
      if (!items.childElementCount) items.textContent = q ? '没有匹配的账号。' : '还没有账号。';
    }
    el('search').oninput = render; render();
  }
  function edit(entry) {
    page(`<section class="card"><h1>${entry ? '编辑账号' : '新增账号'}</h1><form>
      <label>网站或应用<input id="site" required maxlength="500"></label><label>账号<input id="account" maxlength="1000" autocomplete="off"></label>
      <label>密码<input id="password" type="password" required autocomplete="off"></label>
      <div class="row"><button id="show" type="button">显示密码</button><button type="button" id="copy">复制密码</button></div>
      <label>备注<textarea id="notes" maxlength="12000"></textarea></label><div class="row">
      <button class="primary">保存</button><button id="back" type="button">返回</button>
      ${entry ? '<button id="delete" type="button" class="danger">删除账号</button>' : ''}</div></form></section>`);
    for (const id of ['site','account','password','notes']) el(id).value = entry?.[id] || '';
    click('back', list);
    click('show', () => {
      const show = el('password').type === 'password';
      el('password').type = show ? 'text' : 'password';
      el('show').textContent = show ? '隐藏密码' : '显示密码';
    });
    click('copy', () => copyValue(el('password').value));
    if (entry) click('delete', () => {
      el('delete').textContent = '确认删除这条账号';
      click('delete', () => run(ticket => save(ticket, { ...session, entries: session.entries.filter(e => e.id !== entry.id) })));
    });
    formAction(async ticket => {
      const record = { id: entry?.id || crypto.randomUUID(), site: el('site').value.trim(), account: el('account').value,
        password: el('password').value, notes: el('notes').value };
      if (!record.site) throw new Error('请填写网站或应用名称。');
      const entries = entry ? session.entries.map(e => e.id === entry.id ? record : e) : [...session.entries, record];
      await save(ticket, { ...session, entries });
    });
  }
  function copyValue(value) {
    const temp = document.createElement('textarea');
    temp.style.cssText = 'position:fixed;left:-9999px';
    temp.value = value; document.body.append(temp); temp.select();
    try { notice.textContent = document.execCommand('copy') ? '已复制到系统剪贴板。' : '复制不可用，请显示并手动复制。'; }
    finally { temp.value = ''; temp.remove(); }
  }
  function backup() {
    page(`<section class="card"><h1>加密备份</h1><p>将整段备份保存到自己的文件。恢复时需要备份当天的主密码。</p>
      <label>加密备份文本<textarea id="data" readonly></textarea></label><div class="row">
      <button id="copy">复制备份</button><button id="restore">从备份恢复</button><button id="back">返回</button></div></section>`);
    el('data').value = snapshot.value;
    click('copy', () => copyValue(snapshot.value)); click('restore', restore); click('back', list);
  }
  function restore() {
    page(`<section class="card"><h1>恢复加密备份</h1><form><label>备份文本<textarea id="data" required maxlength="4194304"></textarea></label>
      <label>备份的主密码<input id="backupPw" type="password" autocomplete="off" required></label>
      <p>${session ? '恢复将替换本库全部账号，继续使用当前主密码。' : '恢复后使用这份备份的主密码解锁。'}</p>
      <div class="row"><button class="primary">确认恢复</button><button type="button" id="back">取消</button></div></form></section>`);
    click('back', session ? list : () => run(load));
    formAction(async ticket => {
      const other = await decrypt(el('data').value.trim(), el('backupPw').value);
      check(ticket);
      await save(ticket, { ...(session || other), entries: other.entries });
    });
  }
  function change() {
    page(`<section class="card narrow"><h1>修改主密码</h1><form><label>当前主密码<input id="old" type="password" required autocomplete="off"></label>
      <label>新主密码<input id="next" type="password" required autocomplete="off"></label>
      <label>确认新主密码<input id="confirm" type="password" required autocomplete="off"></label>
      <div class="row"><button class="primary">保存新主密码</button><button id="back" type="button">取消</button></div></form></section>`);
    click('back', list);
    formAction(async ticket => {
      const password = el('next').value;
      validateNew(password, el('confirm').value);
      await decrypt(snapshot.value, el('old').value); check(ticket);
      const salt = crypto.getRandomValues(new Uint8Array(16));
      await save(ticket, { entries: session.entries, salt, key: await derive(password, salt) });
    });
  }
  lock();
  await run(load);
})();
