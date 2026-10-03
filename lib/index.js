// dsh-file-opener — 服务端半边
//
// 三个端点：/dsh-fo/info（路径 → kind=file|dir|missing + size + text）、/dsh-fo/open（POST：目录走
// explorer.exe，文件走 powershell Invoke-Item）、/dsh-fo/diag（内存环形缓冲，最近 64 条）。
// 三者最前面都过一道照官方 isTrustedApiRequest 实现的信任围栏：Host 必须是回环或本部署对外服务的
// 权威，且拒 sec-fetch-site: cross-site——只比 Origin 与 Host 相等挡不住 DNS rebinding。
// 约束：只用官方 webServer 公开契约；打开动作用系统命令自己实现，**不 import 官方内部包**
// （那是给下次升级埋雷）；无硬编码路径（主目录走 os.homedir()）；不写运行状态文件。
// 实测记录、为什么不去够官方 RPC、围栏的完整理由见 README「踩过的坑」「原理」。
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { pathToFileURL } from 'node:url'
import { spawn } from 'node:child_process'

const fsp = fs.promises

export const name = 'dsh-file-opener'
export const inject = ['webServer']

const JSON_HEADERS = {
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'no-store',
}

// 统一的错误文本：一律截 200 字符，别把整段堆栈塞进响应和诊断缓冲
function errText(err) {
  return String((err && err.message) || err).slice(0, 200)
}

// ================= 内存诊断环形缓冲（零文件写入） =================
const DIAG_LIMIT = 64
const diagEvents = []

function logDiag(kind, detail) {
  diagEvents.push({
    t: Date.now(),
    kind,
    detail: String(detail == null ? '' : detail).slice(0, 300),
  })
  if (diagEvents.length > DIAG_LIMIT) {
    diagEvents.splice(0, diagEvents.length - DIAG_LIMIT)
  }
}

// ================= 访问控制：官方信任围栏的等价实现 =================
// 插件走 ctx.webServer.register 自己注册路由，本来就在官方 /api 围栏（isTrustedApiRequest）外面，
// 所以自己补一份等价判据：Host 必须是回环（localhost / [::1] / 127.0.0.0/8）或本部署对外服务的
// 权威（trustedHosts）；sec-fetch-site: cross-site 一律拒；带 Origin 时还要与 Host 同源。
// **Host 那条才是挡 DNS rebinding 的关键**：重绑之后 Host 仍是攻击者的域名、与页面 Origin 天然
// 相等，只比 Origin 与 Host 相等等于没拦。不带 Origin 但 Host 回环的照常放行（能在本机跑脚本的人
// 本来就能直接读盘，拦它只会把排查和自测一起拦死）——刻意保留，不要改掉。
function isLoopbackHostname(hostname) {
  if (hostname === 'localhost' || hostname === '[::1]') return true
  const parts = String(hostname).split('.')
  return parts.length === 4 && parts[0] === '127'
    && parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255)
}

function parseAuthority(authority) {
  try { return new URL(`http://${authority}`) } catch { return undefined }
}

// 权威的规范形：写了端口就是 hostname:port，没写就是 hostname（默认端口按两种 scheme 分别判）
function canonicalAuthority(entry, entryUrl) {
  const port = entryUrl.port !== '' ? entryUrl.port : new URL(`https://${entry}`).port
  return port === '' ? entryUrl.hostname : `${entryUrl.hostname}:${port}`
}

// trustedHosts 条目是裸 authority：带端口的按 hostname:port 精确比，不带端口的只比 hostname（任意端口）
function isTrustedAuthority(hostUrl, trustedHosts) {
  return trustedHosts.some((entry) => {
    const entryUrl = parseAuthority(entry)
    if (entryUrl === undefined) return false
    return canonicalAuthority(entry, entryUrl) === entryUrl.hostname
      ? entryUrl.hostname === hostUrl.hostname
      : entryUrl.host === hostUrl.host
  })
}

// Node 的 req.headers 键名已是小写；这里再容错一层，方便自测直接塞普通对象
function headerOf(headers, name) {
  if (!headers) return undefined
  const v = headers[name] !== undefined ? headers[name] : headers[name.toLowerCase()]
  if (typeof v === 'string') return v
  if (Array.isArray(v) && typeof v[0] === 'string') return v[0]
  return undefined
}

function isTrustedApiRequest(req, trustedHosts = []) {
  const headers = (req && req.headers) || {}
  const host = headerOf(headers, 'host')
  if (host === undefined) return false
  const hostUrl = parseAuthority(host)
  if (hostUrl === undefined) return false
  if (!isLoopbackHostname(hostUrl.hostname) && !isTrustedAuthority(hostUrl, trustedHosts)) return false
  if (headerOf(headers, 'sec-fetch-site') === 'cross-site') return false
  const origin = headerOf(headers, 'origin')
  if (origin === undefined) return true
  try { return new URL(origin).host === hostUrl.host } catch { return false }
}

// 「本部署对外服务的非回环权威」= webServer 公开的 host/port + 本机所有非内部 IPv4（各带当前端口）。
// 端口要等服务 listen 之后才有，所以惰性计算 + 5 秒缓存；全取不到就只剩回环判据（宁可严不要松）。
let trustedHostsCache = { at: 0, list: [] }
function collectTrustedHosts(ctx) {
  const now = Date.now()
  if (now - trustedHostsCache.at < 5000) return trustedHostsCache.list
  const out = new Set()
  let port = ''
  try {
    const ws = ctx && ctx.webServer
    const p = ws && ws.port
    if (typeof p === 'number' && p > 0) port = String(p)
    const h = ws && ws.host
    // 0.0.0.0 / :: 是通配绑定，不是客户端会写进 Host 的权威，不收
    if (typeof h === 'string' && h && h !== '0.0.0.0' && h !== '::') out.add(port ? `${h}:${port}` : h)
  } catch { /* 取不到就跳过 */ }
  try {
    for (const list of Object.values(os.networkInterfaces())) {
      for (const info of list ?? []) {
        if (info && info.family === 'IPv4' && !info.internal && typeof info.address === 'string') {
          out.add(port ? `${info.address}:${port}` : info.address)
        }
      }
    }
  } catch { /* 取不到就跳过 */ }
  // 拿不到端口就不写缓存：否则会把"任意端口"的裸地址记进缓存，等下一条请求才纠正
  if (port !== '') trustedHostsCache = { at: now, list: [...out] }
  return [...out]
}

function requestRejection(req, ctx) {
  return isTrustedApiRequest(req, collectTrustedHosts(ctx)) ? 0 : 403
}

function wantsJsonBody(req) {
  return /application\/json/i.test(String(req.headers?.['content-type'] || ''))
}

// ================= 路径规范化与 stat =================

// 把对话里的路径文本规范化为绝对路径：展开 ~ / ~/xxx / ~\xxx，去尾部斜杠（保留盘符根 C:\）
function expandMentionPath(raw) {
  let p = String(raw == null ? '' : raw).trim()
  if (!p) return null
  if (p === '~') {
    p = os.homedir()
  } else if (p.startsWith('~/') || p.startsWith('~\\')) {
    p = path.join(os.homedir(), p.slice(2))
  }
  if (!path.isAbsolute(p)) return null
  while (p.length > 3 && (p.endsWith('/') || p.endsWith('\\'))) {
    p = p.slice(0, -1)
  }
  return p
}

// 保留设备名：Windows 把这些名字当设备（不是文件），stat 它们的行为不受普通文件系统约束
const RESERVED_DEVICE_NAMES = new Set([
  'CON', 'PRN', 'AUX', 'NUL',
  ...Array.from({ length: 9 }, (_, i) => `COM${i + 1}`),
  ...Array.from({ length: 9 }, (_, i) => `LPT${i + 1}`),
])

// 既不 stat、也不交给 explorer 的路径（两个端点都直接回 unsupported-path）：
//   - UNC（\\server\share 与 //server/share 两种写法）：指向不可达 IP 时 SMB 要等约 21 秒超时，
//     异步化只解决「阻塞事件循环」，不解决「白白等一次超时」；
//   - 保留设备名（末段去掉扩展名后等于 CON/PRN/AUX/NUL/COM1-9/LPT1-9，大小写不敏感）。
function unsupportedPathReason(abs) {
  const s = String(abs == null ? '' : abs)
  if (s.startsWith('\\\\') || s.startsWith('//')) return 'unc'
  const tail = s.replace(/[\\/]+$/, '').split(/[\\/]/).pop() || ''
  if (!tail) return null
  const dot = tail.indexOf('.')
  const stem = dot === -1 ? tail : tail.slice(0, dot)
  return RESERVED_DEVICE_NAMES.has(stem.toUpperCase()) ? 'device-name' : null
}

// 判断文件"适不适合按纯文本显示"：开头若干字节里没有 NUL，且能整段按 UTF-8 解码。官方右侧在没有
// 专门预览器时会退回纯文本视图，二进制点进去只得到一句「无法预览」——所以提前替它判一次，直接走系统。
// 全程异步：路径由请求方指定，同步 IO 遇到不可达路径会卡住整个宿主事件循环（全站卡死）。
async function looksLikeText(abs, maxBytes = 4096) {
  let fh
  try {
    fh = await fsp.open(abs, 'r')
    const buf = Buffer.alloc(maxBytes)
    const read = await fh.read(buf, 0, maxBytes, 0)
    const n = read.bytesRead
    let slice = buf.subarray(0, n)
    if (slice.includes(0)) return false
    // 读满一整块时，末尾 3 字节可能是被切断的多字节字符，掐掉再判，免得误伤中文文件
    if (n === maxBytes && slice.length > 3) slice = slice.subarray(0, slice.length - 3)
    try {
      new TextDecoder('utf-8', { fatal: true }).decode(slice)
      return true
    } catch {
      return false
    }
  } catch {
    return false
  } finally {
    if (fh !== undefined) { try { await fh.close() } catch { /* ignore */ } }
  }
}

async function statMention(raw) {
  const abs = expandMentionPath(raw)
  if (!abs) return { ok: false, error: 'not-an-absolute-path' }
  if (unsupportedPathReason(abs)) return { ok: false, error: 'unsupported-path', abs }
  let kind = 'missing'
  let size
  try {
    const st = await fsp.stat(abs)
    kind = st.isDirectory() ? 'dir' : 'file'
    size = st.size
  } catch {
    /* 不存在或不可访问 → missing */
  }
  const out = { ok: true, kind, abs, name: path.basename(abs) || abs }
  if (kind === 'file') {
    if (typeof size === 'number') out.size = size
    out.text = await looksLikeText(abs)
  }
  return out
}

// 从给定路径向上找第一个真实存在的目录（含自身）。用途见 /dsh-fo/open 目录分支。
async function nearestExistingDir(abs, maxUp = 6) {
  let cur = String(abs || '')
  for (let i = 0; i <= maxUp; i++) {
    try {
      if ((await fsp.stat(cur)).isDirectory()) return cur
    } catch { /* 继续往上找 */ }
    const parent = path.dirname(cur)
    if (!parent || parent === cur) return null
    cur = parent
  }
  return null
}

// 把"该开哪个真实路径"和"怎么开"分开：解析部分纯查文件系统，自测可直接断言，不必真弹窗口。
async function resolveOpenTarget(abs, what) {
  if (what === 'file') {
    let st
    try {
      st = await fsp.stat(abs)
    } catch {
      return { error: 'not-found' }
    }
    return st.isFile() ? { target: abs } : { error: 'not-a-file' }
  }
  // 目录分支：目标不存在（被改名/挪走/本来写错）就向上退到最近的真实目录，
  // 绝不把不存在的路径丢给 explorer——它会自己去开「文档」还算成功。
  try {
    if ((await fsp.stat(abs)).isDirectory()) return { target: abs, adjusted: false }
  } catch { /* 交给下面的回退 */ }
  const up = await nearestExistingDir(abs)
  if (up === null) return { error: 'no-existing-directory' }
  return { target: up, adjusted: up !== abs }
}

// ================= 两种打开动作 =================

// PowerShell 单引号字面量（内部的 ' 翻倍）——照官方语义自己实现，不依赖官方包。
function powershellLiteral(p) {
  return "'" + String(p).replace(/'/g, "''") + "'"
}

// 系统程序走绝对路径：不靠 PATH 解析（PATH 里靠前的可写目录被放同名程序就是劫持面）；取不到
// SystemRoot 才退回裸名。internals.env / explorerPath / powershellPath 是自测注入点，不影响运行。
function systemExe(internals, key, relParts, bare) {
  const override = internals[key]
  if (typeof override === 'string' && override) return override
  const env = internals.env ?? process.env
  const root = env.SystemRoot || env.windir
  if (!root) return bare
  return path.join(root, ...relParts)
}

// 起一个"分离"的子进程：不等待、不 kill（explorer 的子进程就是窗口进程，kill 会连窗口一起杀掉）。
// 第一个候选（绝对路径）ENOENT 时退回裸名再试一次，保证绝对路径取不到也还能用。
function spawnDetached(spawnFn, candidates, args, opts) {
  return new Promise((resolve) => {
    const attempt = (i) => {
      let child
      try {
        child = spawnFn(candidates[i], args, opts)
      } catch (err) {
        resolve({ ok: false, error: errText(err) })
        return
      }
      if (typeof child.unref === 'function') child.unref()
      let settled = false
      const finish = (v) => { if (!settled) { settled = true; resolve(v) } }
      child.on('error', (err) => {
        if (err && err.code === 'ENOENT' && i + 1 < candidates.length) { attempt(i + 1); return }
        finish({ ok: false, error: errText(err) })
      })
      child.on('spawn', () => finish({ ok: true }))
    }
    attempt(0)
  })
}

// 照官方 native-command 的 explorerTarget：explorer **自己按逗号/等号切分命令行字段**，原始路径里
// 含 , 或 = 会被截断、静默打开别的目标（典型是「文档」库）而进程照样起来、插件还回报成功。
// 做法 = 路径转 file URI，再把 , → %2C、= → %3D；非 ASCII 的百分号转义要还原成字面字符
// （explorer 不认 file URI 里的非 ASCII 百分号转义，会改开「文档」库——官方注释里有实测记录）。
function explorerTarget(abs) {
  const href = pathToFileURL(String(abs), { windows: true }).href
  return href
    .replace(/(?:%[89A-F][0-9A-F])+/gi, (escaped) => decodeURIComponent(escaped))
    .replaceAll(',', '%2C')
    .replaceAll('=', '%3D')
}

// 用 explorer.exe 打开目录（Windows）。路径作为**单个** argv（转义后的 file URI）传入：既避免含空格的
// 路径被 node 整串套上引号、explorer 不认前缀而改开「文档」库，也避免 , 与 = 被 explorer 自己切分字段。
// internals 可注入（平台 + spawn + env），供离线自测不真弹窗。
function openDirectory(abs, internals = {}) {
  const platform = internals.platform ?? process.platform
  const spawnFn = internals.spawn ?? spawn
  if (platform !== 'win32') {
    return Promise.resolve({ ok: false, error: 'unsupported-platform' })
  }
  const exe = systemExe(internals, 'explorerPath', ['explorer.exe'], 'explorer.exe')
  const candidates = exe === 'explorer.exe' ? ['explorer.exe'] : [exe, 'explorer.exe']
  return spawnDetached(spawnFn, candidates, [explorerTarget(abs)], {
    // explorer 是 GUI 程序，windowsHide:false 不会带出黑色控制台；留 node 默认的 true
    // 会被 explorer 尊重而以隐藏方式启动，窗口永远不显示（2026-08-24 实案）。
    windowsHide: false,
    stdio: 'ignore',
    detached: true, // 与宿主进程分离：explorer 进程即文件夹窗口本身，必须让它自己活着
  })
}

// 用系统默认程序打开文件（Windows）。路径走单引号字面量（PS 里逗号不是分隔符，无需额外转义）。
function openFileWithDefault(abs, internals = {}) {
  const platform = internals.platform ?? process.platform
  const spawnFn = internals.spawn ?? spawn
  if (platform !== 'win32') {
    return Promise.resolve({ ok: false, error: 'unsupported-platform' })
  }
  const exe = systemExe(internals, 'powershellPath',
    ['System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'], 'powershell.exe')
  const candidates = exe === 'powershell.exe' ? ['powershell.exe'] : [exe, 'powershell.exe']
  return spawnDetached(spawnFn, candidates, [
    '-NoProfile',
    '-NonInteractive',
    '-WindowStyle', 'Hidden',
    '-Command',
    'Invoke-Item -LiteralPath ' + powershellLiteral(abs),
  ], {
    windowsHide: true, // powershell 是控制台程序，这里必须隐藏，否则闪一个蓝框
    stdio: 'ignore',
    detached: true, // 打开的是别的应用，不该被宿主退出带走
  })
}

// 读取小 JSON body（POST 端点用）。限制按**字节**算；超限回 {ok:false,error:'body-too-large'}
// 并 resume() 把剩下的请求体排空（**不要 destroy()**：socket 一断，调用方就没法再回 413 了）。
function readJsonBody(req, limit = 4096) {
  return new Promise((resolve) => {
    const chunks = []
    let bytes = 0
    let done = false
    const finish = (v) => {
      if (done) return
      done = true
      resolve(v)
    }
    req.on('data', (chunk) => {
      if (done) return
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk))
      bytes += buf.length
      if (bytes > limit) {
        finish({ ok: false, error: 'body-too-large' })
        try { req.resume() } catch { /* ignore */ }
        return
      }
      chunks.push(buf)
    })
    req.on('end', () => {
      if (done) return
      try {
        const text = Buffer.concat(chunks).toString('utf8')
        finish({ ok: true, value: JSON.parse(text || '{}') })
      } catch {
        finish({ ok: false, error: 'bad-json' })
      }
    })
    req.on('error', () => finish({ ok: false, error: 'bad-json' }))
  })
}

function sendJson(res, status, body) {
  res.writeHead(status, JSON_HEADERS)
  res.end(JSON.stringify(body))
}

// body 读失败 → HTTP 状态：超限 413，其余（坏 JSON / 请求出错）400
function bodyErrorStatus(error) {
  return error === 'body-too-large' ? 413 : 400
}

// 两个 POST 端点共用的前置：content-type 不是 JSON 回 415，body 读失败按上表回状态码。
// 这两种情况响应已经发出去，返回 undefined（JSON 文本本身解析不出 undefined，可安全当哨兵）。
async function readJsonRequest(req, res) {
  if (!wantsJsonBody(req)) {
    sendJson(res, 415, { ok: false, error: 'json-body-required' })
    return undefined
  }
  const parsed = await readJsonBody(req)
  if (!parsed.ok) {
    sendJson(res, bodyErrorStatus(parsed.error), { ok: false, error: parsed.error })
    return undefined
  }
  return parsed.value
}

// 纯函数 / 无副作用出口，供离线自测用（不影响运行）
export const _test = {
  expandMentionPath,
  unsupportedPathReason,
  statMention,
  looksLikeText,
  nearestExistingDir,
  resolveOpenTarget,
  openDirectory,
  openFileWithDefault,
  powershellLiteral,
  explorerTarget,
  readJsonBody,
  isLoopbackHostname,
  isTrustedAuthority,
  isTrustedApiRequest,
  collectTrustedHosts,
  requestRejection,
}

export function apply(ctx) {
  const disposers = []

  // ---------- /dsh-fo/info：路径 → kind / size / text ----------
  disposers.push(ctx.webServer.register({
    kind: 'exact',
    path: '/dsh-fo/info',
    handler: async (req, res) => {
      const rej = requestRejection(req, ctx)
      if (rej) return sendJson(res, rej, { ok: false, error: 'forbidden' })
      try {
        const url = new URL(req.url ?? '/', 'http://localhost')
        sendJson(res, 200, await statMention(url.searchParams.get('p') ?? ''))
      } catch (err) {
        sendJson(res, 200, { ok: false, error: errText(err) })
      }
    },
  }))

  // ---------- /dsh-fo/diag：GET 只读；POST + JSON 追加浏览器端事件 ----------
  // 追加事件改成 POST + application/json：网页要发 JSON 必须先过预检，插件不答应跨源 →
  // 恶意页面发不出来（GET ?e= 是简单请求，会被跨源盲发注入伪造事件）。
  disposers.push(ctx.webServer.register({
    kind: 'exact',
    path: '/dsh-fo/diag',
    handler: async (req, res) => {
      const rej = requestRejection(req, ctx)
      if (rej) return sendJson(res, rej, { ok: false, error: 'forbidden' })
      try {
        const method = String(req.method || 'GET').toUpperCase()
        if (method === 'POST') {
          const body = await readJsonRequest(req, res)
          if (body === undefined) return
          const e = body && typeof body.e === 'string' ? body.e : ''
          if (e) logDiag('client', e)
          return sendJson(res, 200, { ok: true, events: diagEvents.slice() })
        }
        if (method !== 'GET' && method !== 'HEAD') {
          return sendJson(res, 405, { ok: false, error: 'get-or-post-only' })
        }
        sendJson(res, 200, { ok: true, events: diagEvents.slice() })
      } catch (err) {
        sendJson(res, 200, { ok: false, error: errText(err) })
      }
    },
  }))

  // ---------- /dsh-fo/open：目录 / 文件两种打开，两条都先校验存在性 ----------
  disposers.push(ctx.webServer.register({
    kind: 'exact',
    path: '/dsh-fo/open',
    handler: async (req, res) => {
      const rej = requestRejection(req, ctx)
      if (rej) return sendJson(res, rej, { ok: false, error: 'forbidden' })
      try {
        if (String(req.method || 'GET').toUpperCase() !== 'POST') {
          return sendJson(res, 405, { ok: false, error: 'post-only' })
        }
        const body = await readJsonRequest(req, res)
        if (body === undefined) return
        const raw = body && typeof body.path === 'string' ? body.path : ''
        const abs = expandMentionPath(raw)
        if (!abs) return sendJson(res, 200, { ok: false, error: 'not-an-absolute-path' })
        // UNC 与保留设备名直接拒：不 stat、不 spawn
        if (unsupportedPathReason(abs)) return sendJson(res, 200, { ok: false, error: 'unsupported-path', abs })
        const what = body && body.what === 'file' ? 'file' : 'dir'

        const resolved = await resolveOpenTarget(abs, what)
        if (resolved.error) return sendJson(res, 200, { ok: false, error: resolved.error, abs })

        if (what === 'file') {
          const result = await openFileWithDefault(resolved.target)
          return sendJson(res, 200, { ...result, abs: resolved.target, what: 'file' })
        }
        const result = await openDirectory(resolved.target)
        return sendJson(res, 200, { ...result, abs: resolved.target, adjusted: !!resolved.adjusted, what: 'dir' })
      } catch (err) {
        sendJson(res, 200, { ok: false, error: errText(err) })
      }
    },
  }))

  ctx.effect(() => () => {
    for (const d of disposers) {
      try { d() } catch { /* ignore */ }
    }
  })
}
