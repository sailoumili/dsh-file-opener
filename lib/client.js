// dsh-file-opener — 客户端半边（浏览器）
// ① 包装（不注册）官方 chatFileMentions：官方解析不中的行内代码 token 若本身是路径，补一个可点击提及；
// ② 提及按钮后补文件夹小图标（文件 → 所在文件夹，目录 → 该目录本身）；③ 无官方按钮的行内代码兜底同上。
// 分流：点文件先问「右侧显示得了吗」（服务端 text=true → 官方 documentPreviews 注册表 → 内置扩展名名单），
// 能显示走右侧、否则走系统默认程序；点目录、点图标一律资源管理器；**Shift + 点文件 = 强制系统打开**。
// 依赖的官方公开契约：chatFileMentions.forClosing(owner, sessionId)、documentPreviews.candidates、
// owner.openFile、sidebarRight.openResource、sessions 快照——任一项取不到一律退化，不抛错不崩；官方服务只包装
// 不注册、停用时原样还原；不 import 内部包、不写 localStorage/文件。实测记录与坑见 README。
window.__ModuleLoader__.load({
	id: "dsh-file-opener",
	factory: (require) => {
		var module = { exports: {} };
		var exports = module.exports;
		Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });

		const name = "dsh-file-opener";
		const inject = [];

		const INFO_URL = "/dsh-fo/info";
		const OPEN_URL = "/dsh-fo/open";
		const DIAG_URL = "/dsh-fo/diag";
		const CSS_ID = "dsh-file-opener";
		const FOLDER_SVG = '<svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 4.5V12.5C2 13.05 2.45 13.5 3 13.5h10c.55 0 1-.45 1-1V5.5c0-.55-.45-1-1-1H8.5L7.5 3H3c-.55 0-1 .45-1 1.5z"/></svg>';

		// ================= 诊断 beacon（宿主内存环形缓冲，零文件写入） =================

		let lastBeaconEvent = "";
		let lastBeaconAt = 0;
		// 走 POST + application/json：GET ?e= 是"简单请求"，恶意网页能跨源盲发往诊断缓冲注入伪造
		// 事件；JSON 必须先过预检，而插件不答应跨源 → 网页发不出来（2026-10-03 改）。
		function beacon(e) {
			try {
				if (typeof fetch !== "function") return;
				const now = Date.now();
				// 同一事件串 500ms 内去重（避免扫描计数类事件刷屏）
				if (e === lastBeaconEvent && now - lastBeaconAt < 500) return;
				lastBeaconEvent = e;
				lastBeaconAt = now;
				fetch(DIAG_URL, {
					method: "POST",
					headers: { "content-type": "application/json" },
					body: JSON.stringify({ e: String(e).slice(0, 300) }),
					cache: "no-store",
				}).catch(() => {});
			} catch (err) { /* 诊断失败不影响功能 */ }
		}
		function msgOf(e) {
			return String((e && (e.message || e)) || "unknown").slice(0, 120);
		}

		// ================= 纯函数：路径识别 =================

		// 结尾句读直接剥；括号类只在"不成对"时才剥——一律剥会把 F:\a\新建文件夹 (2) 砍成 (2，
		// 当成路径不存在 → 静默去开父目录（2026-09-13 实案）。
		const PUNCT_RE = /[.,;:!?。，、；：！？…·"'‘’“”`]/;
		const CLOSER_OF = { ")": "(", "]": "[", "}": "{", ">": "<", "》": "《", "」": "「", "』": "『", "】": "【" };

		function countOf(s, ch) {
			let n = 0;
			for (const c of s) if (c === ch) n++;
			return n;
		}

		function stripTrailing(s) {
			let out = s;
			let prev = "";
			// length > 3 是为了保住盘符根 C:\（三个字符）不被剥掉反斜杠
			while (out.length > 3 && out !== prev) {
				prev = out;
				const last = out.slice(-1);
				if (last === "/" || last === "\\") { out = out.slice(0, -1); continue; }
				if (PUNCT_RE.test(last)) { out = out.slice(0, -1); continue; }
				const open = CLOSER_OF[last];
				// 只有右括号比左括号多（说明它是包在路径外面的句子括号）才剥
				if (open !== undefined && countOf(out, open) < countOf(out, last)) { out = out.slice(0, -1); continue; }
				break;
			}
			return out;
		}

		function normalizeMention(raw) {
			let s = String(raw == null ? "" : raw).trim();
			if (!s) return null;
			s = stripTrailing(s);
			if (s.length < 3) return null;
			const isAbs = /^[A-Za-z]:[\\/]/.test(s) || s.startsWith("\\\\") || /^~([\\/]|$)/.test(s);
			const isRel = /^\.{1,2}[\\/]/.test(s);
			if (!isAbs && !isRel) return null;
			return { raw: s };
		}

		// 取"所在目录"（客户端字符串运算；盘符根 C:\ 保持不变）
		function dirnameOf(s) {
			let t = String(s || "");
			while (t.length > 3 && (t.endsWith("/") || t.endsWith("\\"))) t = t.slice(0, -1);
			const at = Math.max(t.lastIndexOf("/"), t.lastIndexOf("\\"));
			if (at <= 0) return t;
			const dir = t.slice(0, at);
			if (/^[A-Za-z]:$/.test(dir)) return dir + "\\";
			return dir;
		}

		// ================= 纯函数：右侧显示得了吗 =================

		// 只在官方 documentPreviews 注册表问不到时才用这份名单兜底（图片/pdf 靠服务端 text 判定不出来，
		// 必须带上）。tif/tiff/avif 已移除（2026-10-03）：官方把这三个列为"无预览器的二进制后缀"，
		// 留着只会在注册表不可用时把二进制误送进右侧（显示"无法预览"而不是走系统程序）。
		const PREVIEW_FALLBACK_EXTS = new Set([
			"md", "markdown", "mdx", "txt", "log", "csv", "tsv", "json", "jsonc", "yaml", "yml",
			"toml", "ini", "cfg", "conf", "properties", "env", "xml", "html", "htm", "css", "scss",
			"less", "js", "mjs", "cjs", "ts", "tsx", "jsx", "vue", "svelte", "py", "rb", "go", "rs",
			"java", "kt", "c", "h", "cpp", "hpp", "cs", "php", "swift", "dart", "lua", "pl", "r",
			"sql", "sh", "bash", "bat", "cmd", "ps1", "asm",
			"png", "jpg", "jpeg", "gif", "webp", "bmp", "ico", "svg", "pdf",
		]);

		function extOf(pathOrName) {
			const s = String(pathOrName || "").replace(/\\/g, "/").toLowerCase();
			const name = s.slice(s.lastIndexOf("/") + 1);
			const m = /\.([^./]+)$/u.exec(name);
			return m ? m[1] : "";
		}

		// canSidebarShow(name, isText) → true = 交给右侧打开；false = 交给系统默认程序
		function canSidebarShow(name, isText) {
			if (isText === true) return true; // 官方右侧有纯文本兜底视图
			const cands = registryCandidates(name);
			if (cands !== null) return cands.length > 0;
			return PREVIEW_FALLBACK_EXTS.has(extOf(name));
		}

		// ================= 打开动作 =================

		let currentOpen = null;   // 最近一次 forClosing 拿到的官方 openFile（在右侧打开；相对路径按会话 cwd 解析）
		let clientCtx = null;     // 客户端 ctx（点击时惰性取官方服务）

		// 只读官方 documentPreviews 注册表：问不到返回 null（调用方自己退化成扩展名名单）
		function registryCandidates(nameOrPath) {
			try {
				const reg = clientCtx ? clientCtx.get("documentPreviews") : null;
				if (!reg || typeof reg.candidates !== "function") return null;
				const list = reg.candidates(String(nameOrPath || ""));
				return Array.isArray(list) ? list : null;
			} catch (e) {
				return null;
			}
		}

		// ============ 自建侧边栏通道（2026-09-19 加）============
		// 官方 openFile 的实现就是「取会话 cwd → 拼 dsh-resource 地址 → ctx.sidebarRight.openResource」，
		// 但它只在渲染"某回合最后一条正文"时才递过来：页面刷新 / DSH 重启后有一段拿不到的窗口，那期间
		// 点文件名会掉到系统默认程序；而且它绑定"最后渲染过的会话"，切会话后会指错人。所以自己走同一条路，
		// 地址语法照 @deepseek-ai/dsh-util-workspace-path 的 sessionFileAddress（照抄编码规则，不 require 官方包）；
		// 取不到就返回 false 退回官方钥匙，行为不会比原来差。

		// 照官方 util/workspace-path：绝对路径识别（驱动盘 / UNC / POSIX 斜杠开头）
		function isAbsWorkspacePath(p) {
			const s = String(p || "").replace(/\\/g, "/");
			return s.startsWith("/") || /^[A-Za-z]:\//.test(s) || s.startsWith("//");
		}
		// 照官方 encodeSegment：保留盘符冒号不编码
		function encodeSegment(seg) {
			return encodeURIComponent(seg).replace(/%3A/gi, ":");
		}
		// 照官方 encodePath：按 / 分段编码
		function encodePath(path) {
			return String(path).split("/").map(encodeSegment).join("/");
		}
		// 照官方 sessionFileAddress
		function sessionFileAddress(sessionId, path) {
			const normalized = String(path).replace(/\\/g, "/").replace(/^(?:\.\/)+/, "");
			return "dsh-resource://file/session/" + encodeSegment(sessionId) + "/" + encodePath(normalized);
		}
		// 照官方 chat 的 fileAddressFor：工作区内的绝对路径折成相对 cwd，工作区外整条留着
		function fileAddressFor(sessionId, cwd, path) {
			const normalized = String(path).replace(/\\/g, "/");
			if (!isAbsWorkspacePath(normalized)) return sessionFileAddress(sessionId, normalized);
			const root = cwd == null ? "" : String(cwd).replace(/\\/g, "/").replace(/\/+$/, "");
			if (root !== "" && normalized === root) return sessionFileAddress(sessionId, "");
			if (root !== "" && normalized.startsWith(root + "/")) return sessionFileAddress(sessionId, normalized.slice(root.length + 1));
			return sessionFileAddress(sessionId, normalized);
		}

		// 官方"当前会话"的取法（同官方 dsh-client-ui-workspace）：快照里**没有** current 字段
		// （0.2.0-rc.2 只有 ids/byId/phase/projectionsBySession），读它会恒为 undefined——要看哪一行
		// 被主视图保留，即 retainedBy.mainView > 0。
		function currentSessionRow() {
			try {
				if (!clientCtx || typeof clientCtx.get !== "function") return null;
				const list = clientCtx.get("sessions")?.list?.getSnapshot?.();
				if (!list || !list.byId) return null;
				return Object.values(list.byId).find((row) => ((row && row.retainedBy && row.retainedBy.mainView) || 0) > 0) || null;
			} catch (e) {
				return null;
			}
		}

		// 自己把打开动作送进右侧栏。返回 true = 已送出（不代表内容一定读得出来）。
		function selfSidebarOpen(value) {
			try {
				if (!clientCtx || typeof clientCtx.get !== "function") return false;
				const sr = clientCtx.get("sidebarRight");
				if (!sr || typeof sr.openResource !== "function") return false;
				const row = currentSessionRow();
				const sid = row && row.id ? row.id : null;
				if (!sid) return false;
				sr.openResource(fileAddressFor(sid, row.cwd, value));
				return true;
			} catch (e) {
				beacon("self-sidebar:throw:" + msgOf(e));
				return false;
			}
		}

		// 官方"在右侧打开"。返回 false = 根本没启动（拿不到 openFile 或同步抛错），调用方该改走系统
		function trySidebar(value) {
			// 自建通道优先：会话身份取自"当前正在看的会话"，不受刷新/重启窗口和切会话影响
			if (selfSidebarOpen(value)) { beacon("open-sidebar:self:" + value + ":ok"); return true; }
			if (typeof currentOpen !== "function") return false;
			try {
				const r = currentOpen(value);
				if (r && typeof r.then === "function") {
					r.then(
						() => beacon("open-sidebar:" + value + ":ok"),
						(e) => {
							beacon("open-sidebar:" + value + ":fail:" + msgOf(e) + ":system");
							systemOpen(value);
						}
					);
				} else {
					beacon("open-sidebar:" + value + ":ok");
				}
				return true;
			} catch (e) {
				beacon("open-sidebar:" + value + ":throw:" + msgOf(e));
				return false;
			}
		}

		function postOpen(payload) {
			return fetch(OPEN_URL, {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify(payload),
			}).then((r) => r.json().catch(() => ({ ok: false, error: "bad-response-http-" + r.status })));
		}

		// 目录：资源管理器直开（宿主端 explorer.exe）
		function openDir(pathValue) {
			if (!pathValue) return;
			const isRel = pathValue === "." || pathValue === ".." || pathValue.startsWith("./") || pathValue.startsWith("../");
			if (isRel) {
				// 相对目录没有绝对路径可给 explorer，交给官方 openFile 按会话 cwd 解析
				if (!trySidebar(pathValue)) failOpen(pathValue, "no-absolute-path");
				return;
			}
			postOpen({ path: pathValue, what: "dir" }).then((d) => {
				if (d && d.ok) {
					beacon("open-dir:" + ((d && d.abs) || pathValue) + ":ok" + (d.adjusted ? ":adjusted" : ""));
					return;
				}
				const err = (d && d.error) || "no-response";
				beacon("open-dir:" + pathValue + ":fail:" + err);
				failOpen(pathValue, err);
			}).catch((e) => {
				beacon("open-dir:" + pathValue + ":fail:" + msgOf(e));
				failOpen(pathValue, e);
			});
		}

		// 文件：系统默认程序（宿主端 powershell Invoke-Item）
		function systemOpen(pathValue) {
			if (!pathValue) return;
			postOpen({ path: pathValue, what: "file" }).then((d) => {
				if (d && d.ok) { beacon("open-system:" + pathValue + ":ok"); return; }
				const err = (d && d.error) || "no-response";
				beacon("open-system:" + pathValue + ":fail:" + err);
				if (err === "unsupported-platform") { trySidebar(pathValue); return; } // 非 Windows 宿主：退回右侧
				failOpen(pathValue, err);
			}).catch((e) => {
				beacon("open-system:" + pathValue + ":fail:" + msgOf(e));
				failOpen(pathValue, e);
			});
		}

		// 打开失败要有可见反馈，不能静默（2026-08-23 教训：静默失败让用户以为没反应）
		function failOpen(pathValue, err) {
			const msg = String((err && (err.message || err)) || "未知错误");
			try { console.warn("[file-opener] 打开失败:", pathValue, msg) } catch (e) {}
			try { alert("打开失败：" + pathValue + "\n" + msg) } catch (e) {}
			try {
				const icon = document.querySelector('.dshfo-icon[data-dshfo-p="' + CSS.escape(String(pathValue).slice(0, 64)) + '"]');
				if (!icon) return;
				icon.classList.add("dshfo-err");
				setTimeout(() => icon.classList.remove("dshfo-err"), 1600);
			} catch (e) {}
		}

		// mode: 'open' = 点文字；'folder' = 点文件夹图标。opts.system = 按住 Shift 强制系统打开
		function openMention(p, mode, opts) {
			const forceSystem = !!(opts && opts.system);
			beacon("click:" + mode + (forceSystem ? "+shift" : "") + ":" + p.raw);
			reportContracts();
			fetchInfo(p.raw).then((info) => {
				if (info && info.ok && info.abs) {
					if (info.kind === "missing") { openDir(dirnameOf(info.abs)); return; }
					if (mode === "folder" && info.kind === "file") { openDir(dirnameOf(info.abs)); return; }
					if (info.kind === "dir") { openDir(info.abs); return; }
					// 到这里是文件
					if (forceSystem) { systemOpen(info.abs); return; }
					if (canSidebarShow(info.name, info.text) && trySidebar(info.abs)) return;
					systemOpen(info.abs);
					return;
				}
				// 相对路径或服务端没给结论：点图标打开其目录，点文字交给官方 openFile
				if (mode === "folder") openDir(dirnameOf(p.raw) || p.raw);
				else if (!trySidebar(p.raw)) failOpen(p.raw, "no-absolute-path");
			}).catch(() => {});
		}

		// ================= /dsh-fo/info 查询（去重 + 短缓存） =================
		// 缓存必须带有效期（2026-09-13 实案）：永久缓存的话，文件被改名/挪走/刚新建之后页面不刷新
		// 就一直按旧结论办事——而现在的分流判断（右侧 vs 系统）全靠这个结论。
		const INFO_TTL_MS = 4000;
		const infoCache = new Map();
		const infoInflight = new Map();
		function fetchInfo(raw) {
			const hit = infoCache.get(raw);
			if (hit && Date.now() - hit.at < INFO_TTL_MS) return Promise.resolve(hit.v);
			if (infoInflight.has(raw)) return infoInflight.get(raw);
			const task = fetch(INFO_URL + "?" + new URLSearchParams({ p: raw }), { cache: "no-store" })
				.then((r) => r.json())
				.then((d) => {
					const v = d && d.ok ? d : { ok: false, error: "bad-response" };
					if (infoCache.size > 800) infoCache.clear();
					infoCache.set(raw, { v, at: Date.now() });
					return v;
				})
				.catch(() => ({ ok: false, error: "network" }))
				.finally(() => infoInflight.delete(raw));
			infoInflight.set(raw, task);
			return task;
		}

		// ================= 官方契约体检（升级时一眼看出哪条断了） =================
		// 五样：chatFileMentions（官方路径按钮服务）、documentPreviews（右侧可预览类型注册表）、
		// owner.openFile（官方递过来的右侧打开动作）、sidebarRight.openResource（自建通道用的服务）、
		// sessions 当前会话（retainedBy.mainView，自建通道的会话身份）。取不到就退化成"一律系统打开"，不崩。
		let lastContractLine = "";
		function reportContracts() {
			try {
				const cfm = !!(clientCtx && clientCtx.get("chatFileMentions"));
				const dp = !!(clientCtx && typeof clientCtx.get("documentPreviews")?.candidates === "function");
				const of = typeof currentOpen === "function";
				const sr = !!(clientCtx && typeof clientCtx.get("sidebarRight")?.openResource === "function");
				const curSession = !!currentSessionRow();
				const line = "contracts:cfm=" + (cfm ? 1 : 0) + ",dp=" + (dp ? 1 : 0) + ",openFile=" + (of ? 1 : 0) + ",selfSidebar=" + (sr ? 1 : 0) + ",curSession=" + (curSession ? 1 : 0);
				if (line === lastContractLine) return;
				lastContractLine = line;
				beacon(line);
			} catch (e) { /* 体检失败不影响功能 */ }
		}

		// ================= chatFileMentions（官方机制：包装，不重新注册） =================

		// 2026-08-23 教训：客户端根上下文同一服务只允许注册一次——官方 dsh-client-ui-deliverables 已
		// ctx.provide("chatFileMentions")，这里再 provide 会抛 "service has been registered"、整包加载失败。
		// 所以直接补丁官方服务对象上的 forClosing（不注册新服务）：先问官方（产出文件），再补自己的路径解析；
		// 官方服务未就绪时纯靠下方 DOM 增强兜底。
		function apply(ctx) {
			clientCtx = ctx;
			beacon("apply");

			// 官方服务可能晚于本插件激活（inject 门控），所以轮询等待出现后再补丁
			// （2026-08-23 实案：立即激活时拿不到服务 → 按钮保持官方原始行为）。
			let patchTimer = null;
			let patched = false;
			let restore = null;   // { service, original } —— 插件停用时把官方函数原样还回去
			function stopPolling() {
				if (patchTimer) { clearInterval(patchTimer); patchTimer = null; }
			}
			function ensurePatched() {
				if (patched) { stopPolling(); return; }
				const official = ctx.get("chatFileMentions");
				if (!official || typeof official.forClosing !== "function") return;
				if (official.__dshfoWrapped) {
					// 已被（上一次实例的）补丁包过：认作完成并停轮询，否则会一直空转（2026-09-13 修）
					patched = true;
					stopPolling();
					return;
				}
				const original = official.forClosing;
				const origForClosing = original.bind(official);
				try { Object.defineProperty(official, "__dshfoWrapped", { value: true, configurable: true }); }
				catch (e) { official.__dshfoWrapped = true; }
				// 官方签名是 forClosing(owner, sessionId)（见 dsh-client-ui-chat 的调用点），
				// 少传第二个参数会让产物文件打开变成 /api/present.open?sessionId=undefined → 404
				// （2026-09-13 实案，旧代码就丢了这个参数）
				official.forClosing = (owner, sessionId) => {
					if (owner && typeof owner.openFile === "function") currentOpen = owner.openFile;
					const prevResolver = origForClosing(owner, sessionId);
					return {
						resolve(value) {
							let h = null;
							try { h = prevResolver ? prevResolver.resolve(value) : null; } catch (e) { h = null; }
							if (h) return h;
							const p = normalizeMention(value);
							if (!p) return undefined;
							return {
								title: p.raw,
								label: "打开 " + p.raw,
								open: () => { openMention(p, "open"); },
							};
						},
					};
				};
				restore = { service: official, original };
				patched = true;
				stopPolling();
				beacon("patch");
				reportContracts();
			}
			ensurePatched();
			if (!patched) patchTimer = setInterval(ensurePatched, 100);
			// documentPreviews / openFile 都可能比补丁更晚就绪，稍后再体检一次
			setTimeout(reportContracts, 3000);

			// ============ DOM 层：文件夹小图标（加法操作，可安全退化） ============

			const STYLE = [
				".dshfo-icon{display:inline-flex;align-items:center;justify-content:center;vertical-align:-2px;width:15px;height:15px;margin-left:3px;padding:0;border:none;border-radius:4px;background:transparent;color:inherit;opacity:.75;cursor:pointer;line-height:0}",
				".dshfo-icon:hover,.dshfo-icon:focus-visible{opacity:1;background:rgba(127,127,127,.16);outline:none}",
				"code.dshfo-path{cursor:pointer;text-decoration:underline solid rgba(128,128,128,.55);text-underline-offset:3px}",
				"code.dshfo-path:hover{text-decoration:underline}",
				// 官方路径按钮：用正文颜色 + 下划线表示可点击（覆盖官方的蓝色）
				"code > button[title]:not(.dshfo-icon){color:inherit !important;text-decoration:underline;text-underline-offset:2px}",
				"code > button[title]:not(.dshfo-icon):hover{color:inherit !important;text-decoration:underline}",
			].join("\n");

			function injectStyle() {
				if (typeof document === "undefined") return;
				if (document.querySelector("style[data-plugin-css=" + JSON.stringify(CSS_ID) + "]")) return;
				const tag = document.createElement("style");
				tag.dataset.plugin = name;
				tag.dataset.pluginCss = CSS_ID;
				tag.textContent = STYLE;
				document.head.appendChild(tag);
			}

			function findContainer() {
				if (typeof document === "undefined") return null;
				return document.querySelector("[data-conversation-scroll]")
					|| document.querySelector("[data-chat-flow]")
					|| document.body;
			}

			function makeIcon(rawPath) {
				const icon = document.createElement("button");
				icon.type = "button";
				icon.className = "dshfo-icon";
				icon.dataset.dshfoP = rawPath;
				icon.title = "打开所在文件夹";
				icon.setAttribute("aria-label", "打开所在文件夹");
				icon.innerHTML = FOLDER_SVG;
				return icon;
			}

			function enrichIcon(icon) {
				const raw = icon.dataset.dshfoP;
				if (!raw || icon.dataset.dshfoDone) return;
				icon.dataset.dshfoDone = "1";
				fetchInfo(raw).then((info) => {
					if (!info || !info.ok || !info.abs) return;
					icon.title = info.kind === "dir"
						? "打开文件夹：" + info.abs
						: "打开所在文件夹：" + info.abs;
				}).catch(() => {});
			}

			function unwrapCode(codeEl) {
				codeEl.classList.remove("dshfo-path");
				delete codeEl.dataset.dshfoP;
				delete codeEl.dataset.dshfoT;
				const last = codeEl.lastElementChild;
				if (last && last.classList && last.classList.contains("dshfo-icon")) last.remove();
			}

			function syncIcons(container) {
				if (!container || !container.querySelectorAll) return;
				let added = 0;
				// 1) 官方按钮（code > button[title]）：补文件夹图标。只认"下一个兄弟不是图标"，不用
				//    元素身份缓存——React 流式重渲染会重建按钮节点，旧图标被孤儿清理后必须能重新补上
				//    （2026-08-23 实案：WeakSet 短路过早，导致图标永久缺失）。
				const buttons = container.querySelectorAll("code > button[title]:not(.dshfo-icon)");
				for (const btn of buttons) {
					const next = btn.nextElementSibling;
					if (next && next.classList && next.classList.contains("dshfo-icon")) continue;
					const icon = makeIcon(btn.title || btn.textContent);
					btn.insertAdjacentElement("afterend", icon);
					enrichIcon(icon);
					added++;
				}
				// 2) 普通行内代码兜底（用户消息等）：本身是路径 → 可点击 + 图标
				const codes = container.querySelectorAll("code");
				for (const codeEl of codes) {
					if (codeEl.closest && codeEl.closest("pre")) continue; // 代码块不动
					if (codeEl.classList.contains("dshfo-path")) {
						if (codeEl.dataset.dshfoT !== codeEl.textContent) unwrapCode(codeEl); // 流式内容变了 → 重新评估
						else continue;
					}
					if (codeEl.querySelector("button")) continue; // 已是官方按钮
					const p = normalizeMention(codeEl.textContent);
					if (!p) continue;
					codeEl.classList.add("dshfo-path");
					codeEl.dataset.dshfoP = p.raw;
					codeEl.dataset.dshfoT = codeEl.textContent;
					if (!(codeEl.lastElementChild && codeEl.lastElementChild.classList.contains("dshfo-icon"))) {
						codeEl.appendChild(makeIcon(p.raw));
						added++;
					}
				}
				// 3) 清理孤儿图标（对应按钮/代码被 React 换掉时）
				// 两种归属：A=跟在官方按钮后（同在 code 内）；B=兜底 code 的最后一个子元素
				const icons = container.querySelectorAll(".dshfo-icon");
				for (const icon of icons) {
					const parent = icon.parentElement;
					const prev = icon.previousElementSibling;
					const ok = (prev !== null
							&& prev.tagName === "BUTTON" && !prev.classList.contains("dshfo-icon") && prev.title === icon.dataset.dshfoP)
						|| (parent !== null
							&& parent.tagName === "CODE" && parent.classList.contains("dshfo-path")
							&& parent.dataset.dshfoP === icon.dataset.dshfoP && parent.lastElementChild === icon);
					if (!ok) icon.remove();
				}
				if (added > 0) beacon("icons:" + added);
			}

			function onClick(ev) {
				const target = ev.target;
				if (!target || typeof target.closest !== "function") return;
				const icon = target.closest(".dshfo-icon");
				if (icon) {
					ev.preventDefault();
					ev.stopPropagation();
					const p = normalizeMention(icon.dataset.dshfoP || "");
					if (p) openMention(p, "folder");
					return;
				}
				const codeEl = target.closest("code.dshfo-path");
				if (codeEl) {
					ev.preventDefault();
					ev.stopPropagation();
					const p = normalizeMention(codeEl.dataset.dshfoP || codeEl.textContent);
					if (p) openMention(p, "open", { system: !!ev.shiftKey });
					return;
				}
				// Shift + 点官方按钮：抢在官方 open() 之前拦下，强制用系统默认程序打开（逃生口）
				if (ev.shiftKey) {
					const btn = target.closest("code > button[title]:not(.dshfo-icon)");
					if (btn) {
						ev.preventDefault();
						ev.stopPropagation();
						const p = normalizeMention(btn.title || btn.textContent);
						if (p) openMention(p, "open", { system: true });
					}
				}
				// 不加 Shift 时官方按钮的点击不拦截（其 open 已走官方/本插件逻辑）
			}

			let observer = null;
			let bodyTimer = null;
			let scanTimer = null;
			// 防抖扫描用 setTimeout 而非 rAF：rAF 在后台标签页/无头渲染下会被节流甚至停摆，扫描卡死
			function scheduleScan() {
				if (scanTimer !== null) return;
				scanTimer = setTimeout(() => {
					scanTimer = null;
					const c = findContainer();
					if (c) syncIcons(c);
				}, 120);
			}

			// 观察者绑 document.body：React 切换会话/重建对话容器时容器节点会被整个替换，绑在容器上的
			// 观察者随之失效（2026-08-23 实测）。body 尚未就绪时（脚本可能在 head 中执行）等
			// DOMContentLoaded + 轮询兜底，保证一定能启动（启动失败 = 图标永远不出现）。
			function startObserver() {
				if (typeof document === "undefined") return;
				if (observer) return;
				const tryStart = () => {
					if (!document.body) return false;
					observer = new MutationObserver(scheduleScan);
					observer.observe(document.body, { childList: true, subtree: true, characterData: true });
					scheduleScan();
					return true;
				};
				if (tryStart()) return;
				const waitBody = () => {
					if (observer) {
						stopBodyWait();
						return;
					}
					if (tryStart()) stopBodyWait();
				};
				function stopBodyWait() {
					if (bodyTimer) { clearInterval(bodyTimer); bodyTimer = null; }
				}
				if (typeof document.addEventListener === "function") {
					document.addEventListener("DOMContentLoaded", waitBody, { once: true });
				}
				bodyTimer = setInterval(waitBody, 200);
			}

			injectStyle();
			if (typeof document !== "undefined") {
				document.addEventListener("click", onClick, true);
				startObserver();
			}

			ctx.effect(() => () => {
				if (observer) { observer.disconnect(); observer = null; }
				if (bodyTimer) { clearInterval(bodyTimer); bodyTimer = null; }
				stopPolling();
				if (scanTimer) { clearTimeout(scanTimer); scanTimer = null; }
				// 还原官方 forClosing：不还原的话，插件关掉/重装后官方服务上还挂着我们的旧包装
				if (restore) {
					try {
						delete restore.service.__dshfoWrapped;
						restore.service.forClosing = restore.original;
					} catch (e) { /* 官方对象冻结就只能留着旧包装，不影响本次卸载 */ }
					restore = null;
					patched = false;
				}
				if (typeof document !== "undefined") {
					document.removeEventListener("click", onClick, true);
					const c = findContainer();
					if (c && c.querySelectorAll) {
						for (const el of c.querySelectorAll(".dshfo-icon")) el.remove();
						for (const el of c.querySelectorAll("code.dshfo-path")) unwrapCode(el);
					}
					const tag = document.querySelector("style[data-plugin-css=" + JSON.stringify(CSS_ID) + "]");
					if (tag) tag.remove();
				}
			});
		}

		exports.name = name;
		exports.inject = inject;
		exports.apply = apply;
		// 纯函数出口，供离线自测用（不影响运行）
		exports._test = { normalizeMention, stripTrailing, dirnameOf, extOf, canSidebarShow, PREVIEW_FALLBACK_EXTS, isAbsWorkspacePath, sessionFileAddress, fileAddressFor, selfSidebarOpen, trySidebar, currentSessionRow, reportContracts };
		return module.exports;
	}
});
