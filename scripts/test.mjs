// dsh-file-opener 离线自测（全程不弹任何窗口、不真开任何程序）；用法：插件目录内 node scripts/test.mjs
//  1) 语法检查两个 lib 文件
//  2) 服务端：假 ctx 捕获路由 → 起真实 http server 打端点（info / diag / open、访问围栏、
//     UNC·设备名拒绝、413 超限 body）
//  3) openDirectory / openFileWithDefault：注入 spawn，断言**真实参数形状**（绝对路径 + file URI 转义）
//  4) resolveOpenTarget / nearestExistingDir：真实临时目录树上跑（不 spawn）
//  5) 客户端：vm 里跑 bundle，验证纯函数与右侧/系统分流；apply 冒烟 + 官方服务补丁 + 自建侧边栏通道
import { createServer, request as httpRequest } from 'node:http'
import { readFileSync, writeFileSync, mkdtempSync, rmSync, mkdirSync } from 'node:fs'
import vm from 'node:vm'
import { fileURLToPath, pathToFileURL } from 'node:url'
import path from 'node:path'
import os from 'node:os'

const root = fileURLToPath(new URL('.', import.meta.url))
const pkgDir = path.resolve(root, '..')
let failures = 0
let passes = 0

function check(label, cond, detail = '') {
  if (cond) { passes++; console.log(`  ✓ ${label}`) }
  else { failures++; console.log(`  ✗ ${label} ${detail}`) }
}

// ---------- 1) 语法 ----------
console.log('== 语法 ==')
{
  try {
    const m = await import(pathToFileURL(path.join(pkgDir, 'lib/index.js')).href)
    check('lib/index.js 语法 OK', typeof m.apply === 'function')
  } catch (e) { check('lib/index.js 语法', false, String(e.message)) }
  try {
    new vm.Script(readFileSync(path.join(pkgDir, 'lib/client.js'), 'utf8'))
    check('lib/client.js 语法 OK', true)
  } catch (e) { check('lib/client.js 语法', false, String(e.message)) }
}

// ---------- 2) 服务端路由注册 ----------
console.log('== 服务端端点 ==')
const mod = await import(pathToFileURL(path.join(pkgDir, 'lib/index.js')).href)
let captured = []
mod.apply({
  webServer: { register(route) { captured.push(route); return () => {} } },
  effect() {},
})
const infoRoute = captured.find((r) => r.path === '/dsh-fo/info')
const diagRoute = captured.find((r) => r.path === '/dsh-fo/diag')
const openRoute = captured.find((r) => r.path === '/dsh-fo/open')
check('注册了三个端点 (info + diag + open)', captured.length === 3 && infoRoute && diagRoute && openRoute)
check('插件名/inject', mod.name === 'dsh-file-opener' && Array.isArray(mod.inject) && mod.inject.includes('webServer'))

// ---------- 2b) 访问围栏（纯函数，照官方 isTrustedApiRequest 的语义） ----------
// 2026-10-03：旧实现只比 Origin 与 Host 相等，DNS rebinding 可完整绕过。这里逐条钉住新判据。
// 注意 collectTrustedHosts 有 5 秒缓存，所以放在任何 HTTP 请求之前断言，缓存才是冷的。
console.log('== 访问围栏（纯函数） ==')
{
  const fence = mod._test.isTrustedApiRequest
  check('Host 回环 + 无 Origin → 放行（本机命令行/自测照常用）', fence({ headers: { host: '127.0.0.1:3080' } }, []) === true)
  check('Host 回环 + 同源 Origin → 放行', fence({ headers: { host: '127.0.0.1:3080', origin: 'http://127.0.0.1:3080' } }, []) === true)
  check('Host 非回环 + Origin 与之相同（DNS rebinding 场景）→ 拒',
    fence({ headers: { host: 'evil.com:3080', origin: 'http://evil.com:3080' } }, []) === false)
  check('Host 缺失 → 拒', fence({ headers: {} }, []) === false)
  check('Host 解析不了 → 拒', fence({ headers: { host: 'a b' } }, []) === false)
  check('Host 回环但 Origin 跨源 → 拒', fence({ headers: { host: '127.0.0.1:3080', origin: 'http://evil.com' } }, []) === false)
  check('sec-fetch-site: cross-site → 拒（即使 Host 回环）',
    fence({ headers: { host: '127.0.0.1:3080', 'sec-fetch-site': 'cross-site' } }, []) === false)
  check('trustedHosts 带端口：精确匹配', fence({ headers: { host: '192.168.1.5:3080' } }, ['192.168.1.5:3080']) === true)
  check('trustedHosts 带端口：别的端口不匹配', fence({ headers: { host: '192.168.1.5:9999' } }, ['192.168.1.5:3080']) === false)
  check('trustedHosts 不带端口：任意端口都匹配', fence({ headers: { host: '192.168.1.5:9999' } }, ['192.168.1.5']) === true)
  check('trustedHosts 大小写不敏感（WHATWG 规范化）', fence({ headers: { host: 'MyBox.Lan:3080' } }, ['mybox.lan:3080']) === true)
  check('localhost / [::1] 放行', fence({ headers: { host: 'localhost:3080' } }, []) === true
    && fence({ headers: { host: '[::1]:3080' } }, []) === true)
  check('127/8 全段放行、128.x 不放行', fence({ headers: { host: '127.9.9.9:1' } }, []) === true
    && fence({ headers: { host: '128.0.0.1:1' } }, []) === false)
  const th = mod._test.collectTrustedHosts({ webServer: { host: '192.168.1.77', port: 3080 } })
  check('collectTrustedHosts 收 webServer 的 host:port', th.includes('192.168.1.77:3080'), JSON.stringify(th))
  check('collectTrustedHosts 不收通配绑定 0.0.0.0', !th.some((x) => x.startsWith('0.0.0.0')), JSON.stringify(th))
  check('设备名/UNC 判定（纯函数）',
    mod._test.unsupportedPathReason('\\\\server\\share\\x') === 'unc'
    && mod._test.unsupportedPathReason('//server/share/x') === 'unc'
    && mod._test.unsupportedPathReason('C:\\CON') === 'device-name'
    && mod._test.unsupportedPathReason('C:\\com1.log') === 'device-name'
    && mod._test.unsupportedPathReason('C:\\work\\console.txt') === null
    && mod._test.unsupportedPathReason('C:\\work\\a.txt') === null)
}

// ---------- 3) 两种打开动作的真实参数形状（注入 spawn） ----------
console.log('== openDirectory / openFileWithDefault（注入 spawn） ==')
{
  const spawned = []
  const fakeSpawn = (cmd, args, opts) => {
    const child = { unrefCalled: false, killCalled: false }
    spawned.push({ cmd, args, opts, child })
    child.on = (ev, cb) => { if (ev === 'spawn') setTimeout(cb, 0); return child }
    child.unref = () => { child.unrefCalled = true }
    child.kill = () => { child.killCalled = true }
    return child
  }
  // 带空格的路径 = 2026-09-13 那个「弹出文档库」bug 的回归测试；含逗号/等号 = 2026-10-03 那个
  // 「explorer 自己切分命令行字段、静默开错目标」bug 的回归测试。现在两种都走同一条路：
  // 路径转 file URI、转义 , 与 =，作为**单个** argv 传给 explorer（照官方 explorerTarget）。
  let r = await mod._test.openDirectory('F:\\a b\\c', { platform: 'win32', spawn: fakeSpawn })
  check('win32 目录 → explorer 绝对路径（不靠 PATH 解析）', r.ok === true && spawned.length === 1
    && path.isAbsolute(spawned[0].cmd) && /[\\/]explorer\.exe$/i.test(spawned[0].cmd), String(spawned[0] && spawned[0].cmd))
  check('win32 目录 → 单个 argv 的 file URI（空格编码 %20）', spawned[0].args.length === 1
    && spawned[0].args[0] === 'file:///F:/a%20b/c', JSON.stringify(spawned[0] && spawned[0].args))
  check('windowsHide:false（留默认 true 会被 explorer 隐藏启动、窗口永不显示）', spawned[0].opts.windowsHide === false)
  check('detached + unref（窗口进程自己活着，不 kill）', spawned[0].opts.detached === true
    && spawned[0].child.unrefCalled === true && spawned[0].child.killCalled === false, JSON.stringify(spawned[0]))

  // 含逗号/等号：explorer 按 , 与 = 切分字段 → 必须转义成 %2C / %3D，否则静默开错目标
  spawned.length = 0
  r = await mod._test.openDirectory('F:\\a\\报告(终稿),v2=终', { platform: 'win32', spawn: fakeSpawn })
  const commaUri = spawned[0] ? spawned[0].args[0] : ''
  check('含逗号/等号的路径 → %2C / %3D 转义（不再有裸 , 与 =）',
    r.ok === true && spawned[0].args.length === 1 && commaUri.includes('%2C') && commaUri.includes('%3D')
    && !commaUri.includes(',') && !commaUri.includes('='), commaUri)
  check('非 ASCII 还原成字面字符（explorer 不认百分号转义的非 ASCII，会改开「文档」）',
    commaUri.startsWith('file:///F:/a/') && commaUri.includes('报告(终稿)'), commaUri)
  check('explorerTarget 直测（官方 explorerTarget 同款语义）',
    mod._test.explorerTarget('F:\\a\\x,y=z') === 'file:///F:/a/x%2Cy%3Dz', mod._test.explorerTarget('F:\\a\\x,y=z'))

  // 绝对路径由 SystemRoot 决定；绝对路径 ENOENT（取不到）→ 退回裸名再试一次
  spawned.length = 0
  await mod._test.openDirectory('F:\\x', { platform: 'win32', spawn: fakeSpawn, env: { SystemRoot: 'D:\\Win' } })
  check('explorer 绝对路径由 SystemRoot 决定', spawned[0].cmd === path.join('D:\\Win', 'explorer.exe'), String(spawned[0] && spawned[0].cmd))
  spawned.length = 0
  const enoentOnAbs = (cmd, args, opts) => {
    const child = {
      on(ev, cb) {
        if (ev === 'error' && cmd !== 'explorer.exe') setTimeout(() => cb(Object.assign(new Error('spawn ENOENT'), { code: 'ENOENT' })), 0)
        if (ev === 'spawn' && cmd === 'explorer.exe') setTimeout(cb, 0)
        return child
      },
      unref() {},
    }
    spawned.push({ cmd, args, opts })
    return child
  }
  r = await mod._test.openDirectory('F:\\x', { platform: 'win32', spawn: enoentOnAbs })
  check('绝对路径取不到（ENOENT）→ 退回裸名 explorer.exe 再试',
    r.ok === true && spawned.length === 2 && spawned[1].cmd === 'explorer.exe', JSON.stringify(spawned.map((s) => s.cmd)))

  // 系统默认程序打开文件 = powershell Invoke-Item -LiteralPath '<路径>'（单引号字面量，空格安全）
  spawned.length = 0
  r = await mod._test.openFileWithDefault("F:\\a b\\它's.txt", { platform: 'win32', spawn: fakeSpawn })
  const cmdStr = spawned[0] ? spawned[0].args[spawned[0].args.length - 1] : ''
  check('win32 文件 → powershell 绝对路径 + Invoke-Item -LiteralPath', r.ok === true && spawned.length === 1
    && path.isAbsolute(spawned[0].cmd) && /[\\/]powershell\.exe$/i.test(spawned[0].cmd)
    && /^Invoke-Item -LiteralPath '/.test(cmdStr), JSON.stringify(spawned))
  check('路径里的空格原样保留、内部单引号翻倍转义',
    cmdStr === "Invoke-Item -LiteralPath 'F:\\a b\\它''s.txt'", cmdStr)
  check('powershell 隐藏控制台窗口', spawned[0].opts.windowsHide === true && spawned[0].args.includes('-WindowStyle'))

  r = await mod._test.openDirectory('F:\\x', { platform: 'darwin', spawn: fakeSpawn })
  check('非 win32 目录 → unsupported', r.ok === false && r.error === 'unsupported-platform')
  r = await mod._test.openFileWithDefault('F:\\x', { platform: 'darwin', spawn: fakeSpawn })
  check('非 win32 文件 → unsupported', r.ok === false && r.error === 'unsupported-platform')
  r = await mod._test.openFileWithDefault('F:\\x', { platform: 'win32', spawn: () => { throw new Error('boom') } })
  check('spawn 抛错 → ok:false 如实回报（不再"假装成功"）', r.ok === false && /boom/.test(r.error))
  check('powershellLiteral 转义', mod._test.powershellLiteral("a'b") === "'a''b'")
}

// ---------- 4) 目标解析（真实临时树，不 spawn） ----------
console.log('== nearestExistingDir / resolveOpenTarget ==')
{
  const base = mkdtempSync(path.join(os.tmpdir(), 'dsh-fo-near-'))
  const inner = path.join(base, '存在')
  const innerFile = path.join(base, '普通文本.txt')
  try {
    mkdirSync(inner)
    writeFileSync(innerFile, '文本\n')
    check('自身是目录 → 返回自身', (await mod._test.nearestExistingDir(base)) === base)
    check('多级不存在 → 退到最近的真实目录',
      (await mod._test.nearestExistingDir(path.join(inner, '没有', '再没有'))) === inner,
      String(await mod._test.nearestExistingDir(path.join(inner, '没有'))))
    check('完全不存在的盘 → null', (await mod._test.nearestExistingDir('Q:\\aaa\\bbb')) === null)

    let t = await mod._test.resolveOpenTarget(inner, 'dir')
    check('dir：真实目录 → 原样开、adjusted=false', t.target === inner && t.adjusted === false, JSON.stringify(t))
    t = await mod._test.resolveOpenTarget(path.join(inner, '已被挪走'), 'dir')
    check('dir：目标被挪走 → 退到最近的真实上级并标记 adjusted', t.target === inner && t.adjusted === true, JSON.stringify(t))
    t = await mod._test.resolveOpenTarget(innerFile, 'file')
    check('file：真实文件 → 原样开', t.target === innerFile, JSON.stringify(t))
    t = await mod._test.resolveOpenTarget(inner, 'file')
    check('file：给的是目录 → not-a-file（不会 spawn）', t.error === 'not-a-file', JSON.stringify(t))
    t = await mod._test.resolveOpenTarget(path.join(base, '查无此文件.md'), 'file')
    check('file：不存在 → not-found（不会 spawn）', t.error === 'not-found', JSON.stringify(t))
  } finally { rmSync(base, { recursive: true, force: true }) }
}

// ---------- 5) 起真实 http server 打端点 ----------
const server = createServer((req, res) => {
  const url = new URL(req.url ?? '/', 'http://localhost')
  if (url.pathname === '/dsh-fo/info') infoRoute.handler(req, res)
  else if (url.pathname === '/dsh-fo/diag') diagRoute.handler(req, res)
  else if (url.pathname === '/dsh-fo/open') openRoute.handler(req, res)
  else { res.writeHead(404); res.end() }
})
await new Promise((r) => server.listen(0, '127.0.0.1', r))
const port = server.address().port
async function callInfo(p) {
  const r = await fetch(`http://127.0.0.1:${port}/dsh-fo/info?p=${encodeURIComponent(p)}`, { cache: 'no-store' })
  return r.json()
}
async function callDiag() {
  const r = await fetch(`http://127.0.0.1:${port}/dsh-fo/diag`, { cache: 'no-store' })
  return r.json()
}
// 追加事件走 POST + JSON（2026-10-03 改：GET ?e= 是"简单请求"，会被跨源盲发注入）
async function postDiag(e) {
  const r = await fetch(`http://127.0.0.1:${port}/dsh-fo/diag`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ e }),
  })
  return { status: r.status, body: await r.json().catch(() => null) }
}
// 只打"必然在 spawn 之前就返回错误"的路径，成功路径交给第 4 节，避免真弹窗口
async function callOpen(payload, headers = { 'content-type': 'application/json' }) {
  const r = await fetch(`http://127.0.0.1:${port}/dsh-fo/open`, {
    method: 'POST', headers, body: JSON.stringify(payload),
  })
  return { status: r.status, body: await r.json().catch(() => null) }
}
function raw({ method = 'GET', path: p = '/', headers = {}, body, setHost = true }) {
  return new Promise((resolve) => {
    const req = httpRequest({ host: '127.0.0.1', port, method, path: p, headers, setHost }, (res) => {
      let data = ''
      res.on('data', (c) => { data += c })
      res.on('end', () => { resolve({ status: res.statusCode, body: data }) })
    })
    req.on('error', (e) => resolve({ status: 0, body: String(e.message) }))
    if (body) req.write(body)
    req.end()
  })
}

const tmpDir = mkdtempSync(path.join(os.tmpdir(), 'dsh-file-opener-dir-'))
const tmpFile = path.join(tmpDir, '普通文本.txt')
const tmpBin = path.join(tmpDir, 'binary.bin')
const tmpSpace = path.join(tmpDir, 'computer use')
try {
  writeFileSync(tmpFile, '你好，这是纯文本。\nsecond line\n')
  writeFileSync(tmpBin, Buffer.from([0x4D, 0x5A, 0x00, 0x01, 0x00, 0x02]))
  mkdirSync(tmpSpace)

  console.log('== info 端点 ==')
  let r = await callInfo(tmpFile)
  check('文件 → kind=file + abs + size', r.ok && r.kind === 'file' && r.abs === tmpFile && typeof r.size === 'number', JSON.stringify(r))
  check('纯文本文件 → text=true', r.text === true, JSON.stringify(r))
  r = await callInfo(tmpBin)
  check('二进制文件（含 NUL）→ text=false', r.ok && r.kind === 'file' && r.text === false, JSON.stringify(r))
  r = await callInfo(tmpSpace)
  check('带空格目录 → kind=dir 且空格保留', r.ok && r.kind === 'dir' && r.abs === tmpSpace, JSON.stringify(r))
  r = await callInfo(tmpDir)
  check('目录 → kind=dir 且不带 text 字段', r.ok && r.kind === 'dir' && r.text === undefined, JSON.stringify(r))
  r = await callInfo(path.join(tmpDir, 'nope.txt'))
  check('不存在 → kind=missing', r.ok && r.kind === 'missing', JSON.stringify(r))
  // 自测不碰 ~/.dsh 下任何文件：用主目录里一个必然不存在的路径验展开逻辑
  r = await callInfo('~/dsh-fo-selftest-missing/settings.yaml')
  check('~ 展开', r.ok && r.abs === path.join(os.homedir(), 'dsh-fo-selftest-missing', 'settings.yaml'), JSON.stringify(r))
  r = await callInfo('~/')
  check('~/ 展开+去斜杠', r.ok && r.abs === os.homedir(), JSON.stringify(r))
  r = await callInfo('relative/path.txt')
  check('相对路径拒绝', r.ok === false, JSON.stringify(r))
  r = await callInfo('')
  check('空路径拒绝', r.ok === false, JSON.stringify(r))
  const rootWin = path.parse(process.cwd()).root
  r = await callInfo(rootWin)
  check('盘符根保留', r.ok && r.abs === rootWin, JSON.stringify(r))

  // 2026-10-03：UNC 与保留设备名直接拒（不 stat）——不可达 UNC 的 SMB 超时会拖住整个宿主
  r = await callInfo('\\\\server\\share\\x.txt')
  check('info：UNC 路径 → unsupported-path（不 stat）', r.ok === false && r.error === 'unsupported-path', JSON.stringify(r))
  r = await callInfo('//server/share/x.txt')
  check('info：// 开头的 UNC 变体 → unsupported-path', r.ok === false && r.error === 'unsupported-path', JSON.stringify(r))
  r = await callInfo('C:\\CON')
  check('info：保留设备名 → unsupported-path', r.ok === false && r.error === 'unsupported-path', JSON.stringify(r))
  r = await callInfo('C:\\COM1.log')
  check('info：设备名带扩展名 → unsupported-path', r.ok === false && r.error === 'unsupported-path', JSON.stringify(r))

  console.log('== diag 端点（GET 只读 + POST 追加 + 超限 413） ==')
  r = await callDiag()
  check('diag 可读', r.ok && Array.isArray(r.events), JSON.stringify(r).slice(0, 120))
  const marker = 'client-apply-' + Date.now()
  let d = await postDiag(marker)
  check('diag POST + JSON 追加 beacon', d.status === 200 && d.body && d.body.ok === true, JSON.stringify(d).slice(0, 140))
  r = await callDiag()
  check('diag 记录了 beacon', r.ok && r.events.some((e) => e.kind === 'client' && e.detail === marker), JSON.stringify(r.events.slice(-2)))
  check('diag 缓冲有上限 64', r.events.length <= 64, String(r.events.length))
  // 写入口从 GET ?e= 改成 POST + JSON：GET 不能再写缓冲
  const blind = 'blind-inject-' + Date.now()
  await fetch(`http://127.0.0.1:${port}/dsh-fo/diag?e=${encodeURIComponent(blind)}`, { cache: 'no-store' })
  r = await callDiag()
  check('GET ?e= 不再写缓冲（跨源盲发注入失效）', !r.events.some((e) => e.detail === blind), JSON.stringify(r.events.slice(-2)))
  d = await raw({ method: 'POST', path: '/dsh-fo/diag', headers: { 'content-type': 'text/plain' }, body: '{"e":"x"}' })
  check('diag 追加要求 JSON（网页简单请求发不出 → 415）', d.status === 415, JSON.stringify(d))
  d = await raw({ method: 'POST', path: '/dsh-fo/diag', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ e: 'x'.repeat(8000) }) })
  check('diag body 超限 → 413 body-too-large（不再 destroy 断连）', d.status === 413 && /body-too-large/.test(d.body), JSON.stringify(d).slice(0, 160))
  d = await raw({ method: 'POST', path: '/dsh-fo/open', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ path: 'F:\\x', pad: 'y'.repeat(8000) }) })
  check('open body 超限 → 413 body-too-large', d.status === 413 && /body-too-large/.test(d.body), JSON.stringify(d).slice(0, 160))

  console.log('== open 端点（访问围栏 + 存在性校验，全部在 spawn 前返回） ==')
  let o = await callOpen({ path: 'relative/path' })
  check('open 拒绝相对路径', o.body && o.body.ok === false && o.body.error === 'not-an-absolute-path', JSON.stringify(o))
  o = await callOpen({ path: '' })
  check('open 拒绝空路径', o.body && o.body.ok === false, JSON.stringify(o))
  o = await callOpen({ what: 'file', path: path.join(tmpDir, '不存在.md') })
  check('open 文件不存在 → not-found', o.status === 200 && o.body.ok === false && o.body.error === 'not-found', JSON.stringify(o))
  o = await callOpen({ what: 'file', path: tmpSpace })
  check('open 文件给的是目录 → not-a-file', o.body && o.body.ok === false && o.body.error === 'not-a-file', JSON.stringify(o))
  o = await callOpen({ path: '\\\\server\\share\\x.txt' })
  check('open 拒绝 UNC 路径 → unsupported-path（不 stat、不 spawn）',
    o.status === 200 && o.body.ok === false && o.body.error === 'unsupported-path', JSON.stringify(o))
  o = await callOpen({ path: '//server/share/x.txt' })
  check('open 拒绝 // 开头的 UNC 变体', o.body && o.body.error === 'unsupported-path', JSON.stringify(o))
  o = await callOpen({ what: 'file', path: 'C:\\NUL' })
  check('open 拒绝保留设备名 → unsupported-path', o.body && o.body.error === 'unsupported-path', JSON.stringify(o))
  o = await callOpen({ what: 'file', path: path.join(tmpDir, 'con.txt') })
  check('open 拒绝设备名带扩展名（con.txt）', o.body && o.body.error === 'unsupported-path', JSON.stringify(o))
  o = await raw({ method: 'GET', path: '/dsh-fo/open' })
  check('open 只认 POST（GET → 405）', o.status === 405, JSON.stringify(o))
  o = await raw({ method: 'POST', path: '/dsh-fo/open', headers: { 'content-type': 'text/plain;charset=UTF-8' }, body: '{"path":"' + tmpDir + '"}' })
  check('open 要求 JSON 格式（网页"简单请求"发不出 → 415）', o.status === 415, JSON.stringify(o))
  o = await raw({ method: 'POST', path: '/dsh-fo/open', headers: { 'content-type': 'application/json', origin: 'http://evil.example' }, body: '{"path":"' + tmpDir + '"}' })
  check('open 拒绝跨源 Origin（403）', o.status === 403, JSON.stringify(o))
  o = await raw({ path: '/dsh-fo/info?p=' + encodeURIComponent(tmpFile), headers: { origin: 'http://evil.example' } })
  check('info 拒绝跨源 Origin（403）', o.status === 403, JSON.stringify(o))
  o = await raw({ path: '/dsh-fo/diag', headers: { origin: 'http://evil.example' } })
  check('diag 拒绝跨源 Origin（403）', o.status === 403, JSON.stringify(o))
  o = await raw({ path: '/dsh-fo/info?p=' + encodeURIComponent(tmpFile), headers: { origin: 'http://127.0.0.1:' + port } })
  check('同源 Origin 放行', o.status === 200 && /"kind":"file"/.test(o.body), JSON.stringify(o).slice(0, 140))
  o = await raw({ path: '/dsh-fo/info?p=' + encodeURIComponent(tmpFile) })
  check('不带 Origin（命令行/本机脚本）放行，排查与自测照常用', o.status === 200, JSON.stringify(o).slice(0, 140))
  // 2026-10-03：围栏照官方 isTrustedApiRequest 重写（Host 才是挡 DNS rebinding 的那一条）
  o = await raw({ path: '/dsh-fo/info?p=' + encodeURIComponent(tmpFile), headers: { host: 'evil.com:3080', origin: 'http://evil.com:3080' } })
  check('DNS rebinding：Host=evil.com 且 Origin 与之相同 → 403', o.status === 403, JSON.stringify(o).slice(0, 140))
  o = await raw({ path: '/dsh-fo/info?p=' + encodeURIComponent(tmpFile), headers: { host: 'evil.com:3080' } })
  check('无 Origin 但 Host 非回环/非本部署权威 → 403', o.status === 403, JSON.stringify(o).slice(0, 140))
  o = await raw({ path: '/dsh-fo/info?p=' + encodeURIComponent(tmpFile), headers: { 'sec-fetch-site': 'cross-site' } })
  check('sec-fetch-site: cross-site → 403（即使 Host 回环）', o.status === 403, JSON.stringify(o).slice(0, 140))
  o = await raw({ path: '/dsh-fo/info?p=' + encodeURIComponent(tmpFile), setHost: false })
  check('Host 缺失 → 请求被拒（Node 解析器直接 400；围栏另见下方 handler 级断言）', o.status !== 200, JSON.stringify(o).slice(0, 140))
  // 没带 Host 的 HTTP/1.1 请求到不了我们的围栏（Node 解析器先 400），所以再直接调 handler 钉死 403
  {
    const fakeRes = { status: 0, body: '', writeHead(s) { this.status = s }, end(b) { this.body = String(b || '') } }
    await infoRoute.handler({ method: 'GET', url: '/dsh-fo/info?p=' + encodeURIComponent(tmpFile), headers: {} }, fakeRes)
    check('Host 缺失 → 围栏 403（handler 级，不依赖 Node 解析器行为）', fakeRes.status === 403, JSON.stringify(fakeRes))
  }
} finally {
  rmSync(tmpDir, { recursive: true, force: true })
}
server.close()

// ---------- 6) 客户端纯函数 ----------
console.log('== 客户端 bundle 加载 ==')
const clientSrc = readFileSync(path.join(pkgDir, 'lib/client.js'), 'utf8')
function loadBundle(extraSandbox = {}) {
  let factory = null
  const sandbox = {
    window: { __ModuleLoader__: { load(reg) { factory = reg.factory } } },
    URLSearchParams, URL, fetch, console,
    requestAnimationFrame: () => {},
    MutationObserver: class { observe() {} disconnect() {} },
    setTimeout, clearTimeout, setInterval, clearInterval,
    ...extraSandbox,
  }
  vm.createContext(sandbox)
  vm.runInContext(clientSrc, sandbox)
  return factory
}
let factory = loadBundle()
check('bundle 注册了 factory', typeof factory === 'function')
if (factory) {
  const clientExports = factory(() => { throw new Error('no require') })
  const t = clientExports._test
  check('导出 name/inject/apply', clientExports.name === 'dsh-file-opener' && Array.isArray(clientExports.inject) && typeof clientExports.apply === 'function')
  // 注释里保留着"官方那条 /api 路由实测 404"的说明，所以先把注释剥掉再断言代码里真的不碰它
  const clientCode = clientSrc.replace(/\/\/[^\n]*/g, '')
  check('不再够官方 /api RPC 通道（0.1.5 实测 404，回归护栏）',
    !clientCode.includes('session.openWorkspacePath') && !clientCode.includes('/api/'),
    JSON.stringify(clientCode.match(/["'`][^"'`]*\/api\/[^"'`]*["'`]/g) || []))

  console.log('== normalizeMention（空格 / 结尾括号 / 句读） ==')
  const cases = [
    ['C:\\work\\outputs\\a.txt', 'C:\\work\\outputs\\a.txt'],
    ['C:/work/outputs/a.txt', 'C:/work/outputs/a.txt'],
    ['C:\\', 'C:\\'],
    ['C:\\x', 'C:\\x'],
    ['C:\\work\\backups\\20260822\\', 'C:\\work\\backups\\20260822'],
    ['~/.dsh/settings.yaml', '~/.dsh/settings.yaml'],
    ['~\\x\\y', '~\\x\\y'],
    ['~', null],
    ['\\\\server\\share\\file.txt', '\\\\server\\share\\file.txt'],
    ['./out/x.txt', './out/x.txt'],
    ['../a/b.txt', '../a/b.txt'],
    ['out/x.txt', null],
    ['https://example.com/a', null],
    ['hello world', null],
    ['a b c', null],
    ['', null],
    ['F:\\x\\y。', 'F:\\x\\y'],
    // 2026-09-13 实案：旧写法一律剥结尾括号，把 (2) 砍成 (2 → 当成不存在 → 静默开父目录
    ['F:\\a\\新建文件夹 (2)', 'F:\\a\\新建文件夹 (2)'],
    ['F:\\a\\报告(终稿).docx', 'F:\\a\\报告(终稿).docx'],
    ['F:\\a\\b.md)', 'F:\\a\\b.md'],
    ['F:\\a\\b.md)', 'F:\\a\\b.md'],
    ['F:\\a\\b.md，', 'F:\\a\\b.md'],
    ['C:\\work\\computer use\\CAD\\', 'C:\\work\\computer use\\CAD'],
    ['F:\\a\\【图纸】目录\\x.dwg', 'F:\\a\\【图纸】目录\\x.dwg'],
  ]
  for (const [input, want] of cases) {
    const got = t.normalizeMention(input)
    check(`normalizeMention(${JSON.stringify(input)}) → ${JSON.stringify(want)}`,
      want === null ? got === null : (got !== null && got.raw === want),
      JSON.stringify(got))
  }

  console.log('== dirnameOf ==')
  const dirCases = [
    ['F:\\a\\b\\c.txt', 'F:\\a\\b'],
    ['F:\\a\\b\\', 'F:\\a'],
    ['F:\\a', 'F:\\'],
    ['C:\\', 'C:\\'],
    ['F:\\', 'F:\\'],
    ['./x.txt', '.'],
    ['..\\x', '..'],
    ['~/.dsh', '~'],
    ['F:\\a\\新建文件夹 (2)\\x.md', 'F:\\a\\新建文件夹 (2)'],
    ['F:\\a\\computer use\\CAD\\x.dwg', 'F:\\a\\computer use\\CAD'],
  ]
  for (const [input, want] of dirCases) {
    const got = t.dirnameOf(input)
    check(`dirnameOf(${JSON.stringify(input)}) → ${JSON.stringify(want)}`, got === want, JSON.stringify(got))
  }

  console.log('== 分流判定 canSidebarShow（注册表问不到时走内置名单兜底） ==')
  check('extOf 取扩展名（大小写不敏感）', t.extOf('F:\\a\\B.MD') === 'md' && t.extOf('F:\\a\\无扩展') === '', t.extOf('F:\\a\\B.MD'))
  check('markdown → 右侧', t.canSidebarShow('报告.md', false) === true)
  check('图片 → 右侧（text 判定不出来，靠名单）', t.canSidebarShow('图 1.png', false) === true)
  check('pdf → 右侧', t.canSidebarShow('图纸.pdf', false) === true)
  check('代码 → 右侧', t.canSidebarShow('sample.mjs', false) === true)
  check('dwg → 系统默认', t.canSidebarShow('平面.dwg', false) === false)
  check('zip → 系统默认', t.canSidebarShow('打包.zip', false) === false)
  check('docx → 系统默认（官方目前没有该预览器）', t.canSidebarShow('说明.docx', false) === false)
  check('未知扩展名但服务端报是纯文本 → 右侧（官方纯文本视图）', t.canSidebarShow('数据.veryrare', true) === true)
  check('未知扩展名且二进制 → 系统默认', t.canSidebarShow('数据.veryrare', false) === false)
  // 2026-10-03：官方把 tif/tiff/avif 列为"无预览器的二进制后缀"，兜底名单里必须去掉
  check('tif/tiff/avif 已从兜底名单移除',
    !t.PREVIEW_FALLBACK_EXTS.has('tif') && !t.PREVIEW_FALLBACK_EXTS.has('tiff') && !t.PREVIEW_FALLBACK_EXTS.has('avif'))
  check('tif → 系统默认（不再误送进右侧）', t.canSidebarShow('扫描件.tif', false) === false)
  check('avif → 系统默认', t.canSidebarShow('照片.avif', false) === false)
  check('png/jpg/svg 仍在名单（真有预览器）',
    t.canSidebarShow('图.png', false) === true && t.canSidebarShow('图.svg', false) === true)

  // ---------- 7) 客户端 apply 冒烟 ----------
  console.log('== 客户端 apply 冒烟 ==')
  const elStub = () => ({
    dataset: {}, classList: { add() {}, remove() {}, contains: () => false },
    setAttribute() {}, textContent: '', innerHTML: '', title: '',
    appendChild() {}, remove() {}, insertAdjacentElement() {},
    querySelector: () => null, querySelectorAll: () => [], closest: () => null,
    nextElementSibling: null, lastElementChild: null, tagName: 'DIV',
  })
  // body 给成可用对象：否则插件会按"body 还没就绪"起一个 200ms 等待轮询，
  // 那会让下面"不该留轮询"的断言误报
  const dom = {
    querySelector: () => null, querySelectorAll: () => [],
    createElement: elStub, head: { appendChild() {} },
    addEventListener() {}, removeEventListener() {},
    body: { querySelector: () => null, querySelectorAll: () => [] },
  }
  let provideCalls = []
  let cleanup = null
  const fakeClientCtx = {
    get: () => undefined,
    provide: (k, v) => { provideCalls.push([k, v]) },
    effect: (fn) => { cleanup = fn() },
  }
  factory = loadBundle({ document: dom })
  try {
    const ex = factory(() => { throw new Error('no require') })
    ex.apply(fakeClientCtx)
    check('apply 不抛错（官方服务还没就绪也不能炸）', true)
    check('未注册新服务（官方已注册 chatFileMentions，重复 provide 会抛错）', provideCalls.length === 0, JSON.stringify(provideCalls))
    if (cleanup) { cleanup(); check('卸载回调不抛错', true) } else check('effect 注册', false)
  } catch (e) {
    check('apply 不抛错', false, String((e && e.stack) || e))
  }

  // ---------- 8) 官方服务补丁：sessionId 透传 / 卸载还原 / 轮询不空转 ----------
  console.log('== 官方服务补丁 ==')
  const seenArgs = []
  const origFn = function forClosing(owner, sessionId) {
    seenArgs.push([owner, sessionId])
    return {
      resolve(v) {
        return v === '官方产物路径' ? { title: 'official', open() {} } : undefined
      },
    }
  }
  const official = { forClosing: origFn }
  let cleanup2 = null
  const liveIntervals = new Set()
  const timerSandbox = {
    document: dom,
    setInterval: (fn, ms) => { const id = setInterval(fn, ms); liveIntervals.add(id); return id },
    clearInterval: (id) => { liveIntervals.delete(id); clearInterval(id) },
  }
  const fakeCtx2 = {
    get: (k) => (k === 'chatFileMentions' ? official : undefined),
    provide: () => { throw new Error('重复 provide 应被禁止') },
    effect: (fn) => { cleanup2 = fn() },
  }
  try {
    factory = loadBundle(timerSandbox)
    const ex = factory(() => { throw new Error('no require') })
    ex.apply(fakeCtx2)
    check('apply 不抛错', true)
    check('官方服务被补丁包装', typeof official.forClosing === 'function' && official.__dshfoWrapped === true)
    check('服务已就绪 → 不留轮询空转', liveIntervals.size === 0, 'live=' + liveIntervals.size)
    const resolver = official.forClosing({ openFile() {} }, 'sess-42')
    check('sessionId 透传给官方（丢了就=产物文件打开 404）',
      seenArgs.length === 1 && seenArgs[0][1] === 'sess-42', JSON.stringify(seenArgs.map((a) => a[1])))
    const hOfficial = resolver.resolve('官方产物路径')
    const hMine = resolver.resolve('C:\\work\\outputs\\a.txt')
    const hPlain = resolver.resolve('hello world')
    check('官方解析优先', hOfficial !== undefined && hOfficial.title === 'official')
    check('自己补路径解析（title 必须是干净路径，文件夹图标靠它认路径）',
      hMine !== undefined && hMine.title === 'C:\\work\\outputs\\a.txt', JSON.stringify(hMine && hMine.title))
    check('label 带"打开"前缀', hMine !== undefined && hMine.label === '打开 C:\\work\\outputs\\a.txt', JSON.stringify(hMine && hMine.label))
    check('非路径不解析', hPlain === undefined)
    if (cleanup2) {
      cleanup2()
      check('卸载回调不抛错', true)
      check('卸载后官方 forClosing 被原样还原', official.forClosing === origFn, '仍然是包装后的函数')
      check('卸载后 __dshfoWrapped 标记被清掉', official.__dshfoWrapped === undefined, String(official.__dshfoWrapped))
    } else check('effect 注册', false)

    // 重复激活（热重载/二次 apply）：已被包过 → 认作完成 + 停轮询，不能永久 100ms 空转
    const wrappedFn = official.forClosing
    official.__dshfoWrapped = true
    cleanup2 = null
    factory = loadBundle(timerSandbox)
    const ex2 = factory(() => { throw new Error('no require') })
    ex2.apply(fakeCtx2)
    check('已包装过 → 不重复包装', official.forClosing === wrappedFn)
    if (cleanup2) cleanup2()
    ex2.apply(fakeCtx2)
    check('已包装过 → 轮询会停（旧版会永久空转）', liveIntervals.size === 0, 'live=' + liveIntervals.size)
    liveIntervals.forEach((id) => clearInterval(id))
    liveIntervals.clear()
  } catch (e) {
    check('官方服务补丁场景', false, String((e && e.stack) || e))
  }

  // ---------- 9) 自建侧边栏通道（2026-09-19 加 / 2026-10-03 修）：地址拼接 + 优先于官方钥匙 ----------
  console.log('== 自建侧边栏通道（retainedBy.mainView 取当前会话） ==')
  const opened = []
  let cleanup3 = null
  const passThrough = { forClosing: () => undefined }
  // 官方 0.2.0-rc.2 的快照里**没有 current 字段**：当前会话 = byId 里 retainedBy.mainView > 0 的那一行
  const snapshotWithMain = () => ({
    ids: ['sess-old', 'sess-42'],
    byId: {
      'sess-old': { id: 'sess-old', cwd: 'C:\\', retainedBy: { mainView: 0 } },
      'sess-42': { id: 'sess-42', cwd: 'C:\\work', retainedBy: { mainView: 1 } },
    },
  })
  const fakeCtx3 = {
    get: (k) => {
      if (k === 'chatFileMentions') return passThrough
      if (k === 'sidebarRight') return { openResource: (url) => { opened.push(url) } }
      if (k === 'sessions') return { list: { getSnapshot: snapshotWithMain } }
      return undefined
    },
    provide: () => { throw new Error('不应 provide') },
    effect: (fn) => { cleanup3 = fn() },
  }
  const inWs = 'C:\\work\\中文文件.md'
  const inWsAddr = 'dsh-resource://file/session/sess-42/%E4%B8%AD%E6%96%87%E6%96%87%E4%BB%B6.md'
  const wsRoot = 'C:\\work'
  try {
    factory = loadBundle(timerSandbox)
    const ex3 = factory(() => { throw new Error('no require') })
    ex3.apply(fakeCtx3)
    const t3 = ex3._test
    check('地址：工作区内文件折成相对 cwd',
      t3.fileAddressFor('sess-42', wsRoot, inWs) === inWsAddr, t3.fileAddressFor('sess-42', wsRoot, inWs))
    const outside = 'C:\\Users\\user\\.dsh\\settings.yaml'
    check('地址：工作区外文件整条保留',
      t3.fileAddressFor('sess-42', wsRoot, outside) === 'dsh-resource://file/session/sess-42/C:/Users/user/.dsh/settings.yaml',
      t3.fileAddressFor('sess-42', wsRoot, outside))
    check('地址：盘符冒号不编码、空格与中文分段编码',
      t3.sessionFileAddress('sess-42', 'F:/a b/待办.md') === 'dsh-resource://file/session/sess-42/F:/a%20b/%E5%BE%85%E5%8A%9E.md',
      t3.sessionFileAddress('sess-42', 'F:/a b/待办.md'))
    check('地址：相对路径保留并去掉 ./（Host 按会话 cwd 解析）',
      t3.sessionFileAddress('sess-42', './out/x.md') === 'dsh-resource://file/session/sess-42/out/x.md',
      t3.sessionFileAddress('sess-42', './out/x.md'))
    check('当前会话取 retainedBy.mainView > 0 的那一行（不是 current）',
      t3.currentSessionRow() && t3.currentSessionRow().id === 'sess-42', JSON.stringify(t3.currentSessionRow()))
    check('自建通道把打开动作送进 sidebarRight',
      t3.selfSidebarOpen(inWs) === true && opened[0] === inWsAddr, String(opened[0]))
    check('自建通道优先于官方钥匙', t3.trySidebar(inWs) === true && opened.length === 2, 'opened=' + opened.length)
    if (cleanup3) cleanup3()
  } catch (e) {
    check('自建侧边栏通道场景', false, String((e && e.stack) || e))
  }
  // 快照里没有 retainedBy.mainView > 0 的行（刚刷新 / 主视图还没渲染）→ 优雅返回 false，不抛错
  try {
    factory = loadBundle(timerSandbox)
    const exNoMain = factory(() => { throw new Error('no require') })
    let cleanupNoMain = null
    exNoMain.apply({
      get: (k) => {
        if (k === 'sidebarRight') return { openResource: () => { throw new Error('不该被调用') } }
        if (k === 'sessions') return { list: { getSnapshot: () => ({ byId: { s: { id: 's', cwd: 'F:\\', retainedBy: {} } } }) } }
        return undefined
      },
      provide: () => {},
      effect: (fn) => { cleanupNoMain = fn() },
    })
    const tNo = exNoMain._test
    check('没有 mainView 行 → currentSessionRow 返回 null', tNo.currentSessionRow() === null)
    check('没有 mainView 行 → selfSidebarOpen 优雅返回 false（退回官方 openFile）', tNo.selfSidebarOpen(inWs) === false)
    check('取不到会话 → trySidebar 也返回 false（调用方改走系统）', tNo.trySidebar(inWs) === false)
    if (cleanupNoMain) cleanupNoMain()
  } catch (e) {
    check('无 mainView 场景', false, String((e && e.stack) || e))
  }
  // 回归护栏：旧的坏形状（只有 current、没有 retainedBy）不能被当成当前会话
  try {
    factory = loadBundle(timerSandbox)
    const exOld = factory(() => { throw new Error('no require') })
    let cleanupOld = null
    exOld.apply({
      get: (k) => {
        if (k === 'sidebarRight') return { openResource: () => {} }
        if (k === 'sessions') return { list: { getSnapshot: () => ({ current: 'sess-42', byId: { 'sess-42': { id: 'sess-42', cwd: 'C:\\work' } } }) } }
        return undefined
      },
      provide: () => {},
      effect: (fn) => { cleanupOld = fn() },
    })
    check('旧快照形状（只有 current、无 retainedBy）不再被当当前会话', exOld._test.selfSidebarOpen(inWs) === false)
    if (cleanupOld) cleanupOld()
  } catch (e) {
    check('旧快照形状场景', false, String((e && e.stack) || e))
  }

  // ---------- 9b) 契约体检：5 字段 + curSession 真实反映；beacon 形状（POST + JSON） ----------
  console.log('== 契约体检（curSession）与 beacon 形状 ==')
  {
    const beacons = []
    const fetchStub = (url, opts) => {
      beacons.push({ url, opts })
      return Promise.resolve({ json: async () => ({ ok: true, events: [] }) })
    }
    factory = loadBundle({ ...timerSandbox, fetch: fetchStub })
    const exC = factory(() => { throw new Error('no require') })
    let cleanupC = null
    exC.apply({
      get: (k) => {
        if (k === 'chatFileMentions') return { forClosing: () => undefined }
        if (k === 'sidebarRight') return { openResource: () => {} }
        if (k === 'documentPreviews') return { candidates: () => [] }
        if (k === 'sessions') return { list: { getSnapshot: snapshotWithMain } }
        return undefined
      },
      provide: () => {},
      effect: (fn) => { cleanupC = fn() },
    })
    exC._test.reportContracts()
    const events = beacons.map((b) => { try { return JSON.parse(b.opts.body).e } catch (e) { return '' } })
    const line = events.find((e) => typeof e === 'string' && e.startsWith('contracts:'))
    check('契约体检 5 字段、curSession=1（mainView 取到当前会话）',
      line === 'contracts:cfm=1,dp=1,openFile=0,selfSidebar=1,curSession=1', String(line))
    check('beacon 走 POST + application/json（跨源网页发不出来）',
      beacons.length > 0 && beacons.every((b) => b.opts && b.opts.method === 'POST'
        && /application\/json/i.test(String(b.opts.headers['content-type']))),
      JSON.stringify(beacons[0] && beacons[0].opts && beacons[0].opts.method))
    check('beacon URL 不再带 ?e=', beacons.every((b) => !String(b.url).includes('?')), String(beacons[0] && beacons[0].url))
    check('beacon body 是 {e:"..."}',
      beacons.every((b) => { try { return typeof JSON.parse(b.opts.body).e === 'string' } catch (e) { return false } }))
    if (cleanupC) cleanupC()
  }
  // 两个通道都取不到 → 不抛错，交回调用方走系统默认程序
  try {
    factory = loadBundle(timerSandbox)
    const ex4 = factory(() => { throw new Error('no require') })
    let cleanup4 = null
    ex4.apply({ get: () => undefined, provide: () => {}, effect: (fn) => { cleanup4 = fn() } })
    check('两个通道都取不到 → trySidebar 返回 false（调用方改走系统）', ex4._test.trySidebar('F:\\x\\y.md') === false)
    if (cleanup4) cleanup4()
  } catch (e) {
    check('两通道都取不到场景', false, String((e && e.stack) || e))
  }
}

console.log(failures === 0 ? `\nALL PASS (${passes} checks)` : `\n${failures} FAILURES / ${passes} passed`)
process.exit(failures === 0 ? 0 : 1)
