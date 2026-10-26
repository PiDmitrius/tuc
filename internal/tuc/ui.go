package tuc

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// logo is three bars in the shield of certview narrowing towards its tip,
// the leaves at the top and the root at the bottom, on a grid of 4 so that
// the 16 px favicon renders bars of 2 px and gaps of 1 px.
const logo = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><path fill="#012B6E" d="M32 4L56 12V32Q56 48 32 60Q8 48 8 32V12Z"/><path fill="none" stroke="#fff" stroke-width="8" stroke-linecap="round" d="M20 20H44M24 32H40M28 44H36"/></svg>`

// favicon is the logo with a white rim around the shield, a pixel wide at
// 16 px, so the shield shows on a dark tab too.
var favicon = func() string {
	i := strings.Index(logo, `<path fill="#012B6E" d="`)
	d := logo[i+len(`<path fill="#012B6E" d="`):]
	d = d[:strings.Index(d, `"`)]
	// the rim reaches 4 past the shield (x 8..56, y 4..60), to the edges of the view
	i = strings.Index(logo, `<path fill="#012B6E"`)
	return logo[:i] + `<path fill="none" stroke="#fff" stroke-width="8" stroke-linejoin="round" d="` + d + `"/>` + logo[i:]
}()

var pages = template.Must(template.New("").Funcs(template.FuncMap{
	"time":    func(t time.Time) string { return t.UTC().Format("2006.01.02 15:04:05") + " UTC" },
	"logo":    func() template.HTML { return template.HTML(logo) },
	"logoURL": func() template.URL { return template.URL(url.PathEscape(favicon)) },
}).Parse(`
{{define "head"}}<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>{{.}}</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,{{logoURL}}">
<script>if (/(^#|&)(token|issue)=/.test(location.hash)) document.documentElement.classList.add("pending");
// A script error leaves the page shown and says so, not blank or half-made
// Errors of scripts from elsewhere, such as browser extensions, are theirs
const page = u => String(u).split("#")[0] === location.href.split("#")[0];
const broken = e => { if (e.type === "error" ? !page(e.filename) : !String(e.reason?.stack).includes(location.href.split("#")[0])) return;
  const b = document.getElementById("access-error");
  if (b) { b.textContent = "Страница загрузилась не полностью: " + (e.message || e.reason) + ". Обновите её; если ошибка повторится, сообщите владельцу ТУЦ."; b.classList.remove("hidden"); }
  document.documentElement.classList.remove("pending"); };
addEventListener("error", broken); addEventListener("unhandledrejection", broken);
// A click does not focus row heads and copy cells, so only the keyboard
// shows their focus ring (Safari draws it after a click too)
addEventListener("mousedown", e => { if (e.target.closest?.(".head,.copy") && !e.target.closest("a,button,input,select")) e.preventDefault(); });</script>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scrollbar-gutter:stable;scrollbar-width:thin;scrollbar-color:var(--border) transparent} @supports not (scrollbar-gutter:stable){html{overflow-y:scroll}}
::-webkit-scrollbar{width:10px;height:10px} ::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:5px;border:2px solid var(--bg)} ::-webkit-scrollbar-thumb:hover{background:var(--text2)}
/* a page with an access fragment shows once its layout for that access is final */
.pending main:has(#access-error){visibility:hidden}
:root{--bg:#f6f8fa;--surface:#fff;--border:#d0d7de;--text:#24292e;--text2:#6a737d;--brand:#012b6e;--brand2:#124391;--accent:#2156ad;--tint:#eef2fb;--tint-border:#bfcfe9;--green:#1a7f37;--red:#d73a49;--yellow:#9a6700;--mono:'SF Mono','Cascadia Code','Fira Code',Consolas,monospace}
body{font-family:var(--mono);font-size:13px;line-height:1.5;background:var(--bg);color:var(--text);min-height:100vh}
header{max-width:960px;margin:0 auto;padding:24px 32px 0;display:flex;align-items:center;gap:16px;line-height:normal}
header .logo{display:block;flex:none} header .logo svg{display:block;width:52px;height:52px}
header h1 a{font-family:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;font-size:26px;font-weight:700;line-height:1.15;color:var(--brand);text-decoration:none}
header a:hover{opacity:.85}
header p{color:var(--text2);margin-top:4px;font-size:13px}
main{max-width:960px;margin:0 auto;padding:24px 32px}
a{color:var(--accent)}
.card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:16px}
.card>h2{font-size:14px;font-weight:600;color:var(--brand);margin-bottom:10px}
.position{display:flex;gap:12px;align-items:center;height:20px;margin-bottom:4px;color:var(--text2);font-size:12px;white-space:nowrap}
.position .kind{overflow:hidden;text-overflow:ellipsis;min-width:0} .position>a{flex:none}
.hier{max-height:18rem;overflow:auto} .body .rows{margin:0}
.hier h3{font-size:12px;font-weight:400;color:var(--text2);margin:6px 0 2px}
.hier ol{list-style:none} .hier li{display:flex;gap:8px;align-items:baseline;padding:3px 0}
.hier .lvl{flex:none;width:2ch;text-align:right;color:var(--text2)} .hier .cn{min-width:0;overflow-wrap:anywhere}
.hier .id{flex:none;margin-left:auto;color:var(--text2);font-size:11px}
.title{display:flex;align-items:center;gap:6px;flex-wrap:wrap}
.title h2{font-size:16px;color:var(--brand);flex-basis:100%}
.title h2,main p,table.props td,.head .name{overflow-wrap:anywhere;min-width:0}
.facts{color:var(--text2);margin-top:6px}
.b{display:inline-block;padding:0 8px;border-radius:2em;font-size:11px;line-height:18px;border:1px solid;white-space:nowrap}
.b.blue{color:var(--brand);border-color:var(--brand);background:var(--tint)} .b.green{color:var(--green);border-color:var(--green);background:#dafbe1}
.b.orange{color:var(--yellow);border-color:#bf8700;background:#fff8c5} .b.red{color:var(--red);border-color:var(--red);background:#ffebe9}
.b.mode{display:inline-grid;justify-items:center} .b.mode>*,.b.mode::after{grid-area:1/1} .b.mode::after{content:"Выпуск по ссылке";visibility:hidden} .b.grey{color:var(--text2);border-color:var(--border);background:var(--bg)} .b.solid{color:#fff;border-color:var(--brand);background:var(--brand)}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:10px}
button,a.button{font:inherit;font-size:12px;border:1px solid var(--border);border-radius:6px;background:var(--surface);color:var(--text);padding:4px 12px;cursor:pointer;text-decoration:none;display:inline-block}
button:hover,a.button:hover{border-color:var(--accent);background:var(--tint)}
/* the link to CertView carries its logo, the certview shield */
#certview{display:inline-flex;align-items:center;gap:6px} #certview svg{width:14px;height:14px;flex:none}
button.primary{background:var(--brand);border-color:var(--brand);color:#fff} button.primary:hover{background:var(--brand2);border-color:var(--brand2)}
button.danger{border-color:var(--red);color:var(--red)} button.danger:hover{background:#ffebe9}
button:disabled{opacity:.5;cursor:default}
button:focus-visible,a:focus-visible,input:focus-visible,select:focus-visible,.copy:focus-visible{outline:2px solid var(--accent);outline-offset:1px}
.head:focus-visible{outline:2px solid var(--accent);outline-offset:-2px}
label.field{display:block;margin:8px 0} label.field span{display:block;color:var(--text2);margin-bottom:2px}
.row label.field{flex:1 1 200px;margin:0}
input[type=text],input[type=number],select{width:100%;font:inherit;padding:6px 8px;border:1px solid var(--border);border-radius:6px;background:var(--surface);color:var(--text)}
.seg{display:inline-flex;border:1px solid var(--border);border-radius:6px;overflow:hidden;max-width:100%}
.seg label{padding:3px 10px;cursor:pointer;border-left:1px solid var(--border);white-space:nowrap}
.seg label:first-child{border-left:none}
.seg input{position:absolute;opacity:0;pointer-events:none}
.seg label:has(input:checked){background:var(--tint);color:var(--brand);font-weight:600}
.seg label:has(input:focus-visible){outline:2px solid var(--accent);outline-offset:-2px}
.controls{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
pre{background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:10px;white-space:pre-wrap;word-break:break-all;margin-top:10px}
/* command variants share one place as high as the highest of them */
.cmds{display:grid;margin-top:10px} .cmds>pre{grid-area:1/1;margin:0} .cmds>.off{visibility:hidden} .cmds>.out{display:none}
.note{color:var(--text2);font-size:12px} p.note{min-height:1.5em;margin-top:6px}
.status{min-height:1.2em} .status.error{color:var(--red)} .status.ok{color:var(--green)}
.banner{border-radius:8px;padding:12px 16px;margin-bottom:16px;border:1px solid}
.banner.warn{background:#fff8c5;border-color:#d4a72c} .banner.error{background:#ffebe9;border-color:#ff8182}
.copy{cursor:pointer;word-break:break-all;position:relative} .copy:hover{background:var(--tint)}
.copy.copied::after{content:"скопировано";position:absolute;right:0;bottom:100%;padding:0 4px;border-radius:4px;background:var(--surface);color:var(--green);font-size:11px;white-space:nowrap}
/* Rows that open their detail below: no markers, a tinted
   open row with a rounded brand bar outside the box on its left, short of
   the row's top and bottom. The rows round the corners themselves, as the
   box lets the bar out. */
#public-cas>a{text-decoration:none;color:inherit} #public-cas .id{color:var(--text2);font-size:12px} .rows{background:var(--surface);border:1px solid var(--border);border-radius:8px;margin-bottom:16px} .rows:not(:has(>:not(.hidden))){display:none}
.item{position:relative} .head{border-radius:inherit}
.row:not(:has(>:not(.hidden))){display:none}
.rows>.item:not(.hidden):not(.item:not(.hidden)~.item){border-radius:7px 7px 0 0}
.rows>.item:last-child,#issued-list:not(:has(#more-row:not(.hidden),#list-status:not(:empty))) #certs>.item:last-child{border-radius:0 0 7px 7px}
.item:not(.hidden)~.item{border-top:1px solid var(--border)}
.head{display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding:10px 16px;cursor:pointer}
.head:hover{background:var(--bg)}
.head .name{font-weight:600;color:var(--brand)} .head .meta{color:var(--text2);margin-left:auto}
.item.open{background:var(--tint)}
.item.open::before{content:"";position:absolute;left:-10px;top:6px;bottom:6px;width:4px;border-radius:2px;background:var(--brand)}
.item.open>.head:hover{background:transparent}
.body{padding:0 16px 14px}
.body pre,.body input{background:var(--surface)}
table.props{border-collapse:collapse;width:100%;margin-top:6px;table-layout:fixed} table.props td{padding:4px 8px 4px 0;vertical-align:top}
table.props td:first-child{color:var(--text2);width:150px;white-space:nowrap}
.dn-key{color:var(--text2)} .dn-val{font-weight:600}
.cert .head .name{font-weight:400;color:var(--text)}
.cert .actions{display:flex;flex-wrap:wrap;gap:4px;margin-left:8px}
.search{display:flex;flex-wrap:wrap;gap:8px;padding:10px 16px;border-bottom:1px solid var(--border)}
.search input{flex:1 1 240px;min-width:0} .search button{flex-shrink:0}
.empty{padding:10px 16px;color:var(--text2)} .empty.status:empty{display:none}
.hidden{display:none!important}
@media (max-width:700px){main,header{padding-left:12px;padding-right:12px} .head .meta{margin-left:0;flex-basis:100%} .cert .actions{margin-left:0}
  .seg{flex-direction:column} .seg label{border-left:none;border-top:1px solid var(--border);white-space:normal} .seg label:first-child{border-top:none}}
</style></head><body>
<header><a class="logo" href="/">{{logo}}</a><div><h1><a href="/">ТУЦ</a></h1><p>Тестовые удостоверяющие центры</p></div></header>
<main>{{end}}

{{define "caform"}}
<label class="field"><span>Имя УЦ (DN, время UTC)</span><input type="text" name="subject" required value="{{.Subject}}" aria-describedby="{{if .Child}}child{{else}}root{{end}}-subject-error"></label>
<p class="status error" id="{{if .Child}}child{{else}}root{{end}}-subject-error" data-subject-error></p>
<label class="field"><span>Начало действия, дней от создания</span><input type="number" name="from" value="0" min="-36500" max="36500" required></label>
<label class="field"><span>Срок действия, дней</span><input type="number" name="days" value="3650" min="1" max="36500" required></label>
<label class="field"><span>Алгоритм ключа</span><select name="algo">{{range .Algos}}<option value="{{.}}"{{if eq . $.Alg}} selected{{end}}>{{.Long}}</option>{{end}}</select></label>
<div class="controls"><span class="seg"><label><input type="radio" name="mode" value="open" {{if not .Closed}}checked{{end}}> Открытый</label><label><input type="radio" name="mode" value="closed" {{if .Closed}}checked{{end}}> По ссылке</label></span></div>
{{end}}

{{define "common"}}<script>
const $ = s => document.querySelector(s), $$ = s => [...document.querySelectorAll(s)];
const frag = new URLSearchParams(location.hash.slice(1));
async function call(path, body) {
  let r;
  try { r = await fetch(path, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)}); }
  catch (e) { const x = new Error("Нет связи с сервером"); x.network = true; throw x; }
  const text = await r.text();
  if (!r.ok) { const x = new Error(text.trim() || ("Ошибка " + r.status)); x.status = r.status; throw x; }
  return JSON.parse(text);
}
function status(el, text, kind) { el.textContent = text; el.classList.remove("error", "ok"); if (kind) el.classList.add(kind); }
// writeClipboard copies text; on plain HTTP, where navigator.clipboard is
// missing, through a selected text area.
async function writeClipboard(text) {
  if (navigator.clipboard) return navigator.clipboard.writeText(text);
  const t = document.createElement("textarea");
  t.value = text; t.style.position = "fixed"; t.style.opacity = "0";
  document.body.append(t); t.select();
  const ok = document.execCommand("copy");
  t.remove();
  if (!ok) throw new Error("copy");
}
async function copyText(text, button, label) {
  try { await writeClipboard(text); flash(button, "Скопировано", label); }
  catch (e) { flash(button, "Не скопировано", label); }
}
function copyCell(c, text) {
  const go = e => { e.stopPropagation(); writeClipboard(text).then(() => { c.classList.add("copied"); setTimeout(() => c.classList.remove("copied"), 1200); }, () => {}); };
  c.addEventListener("click", go); c.addEventListener("keydown", e => e.key === "Enter" && go(e));
}
// flash shows text on a button for a moment, keeping the button's width
function flash(el, text, back) {
  el.style.minWidth = el.getBoundingClientRect().width + "px"; el.textContent = text;
  setTimeout(() => { el.textContent = back; el.style.minWidth = ""; }, 1500);
}
// openable makes .item rows open their .body on a click or Enter/Space on
// their .head; links and buttons in the head act without toggling.
function openable(item, onOpen) {
  const head = item.querySelector(".head"), body = item.querySelector(".body");
  head.tabIndex = 0; head.setAttribute("role", "button");
  const set = on => { item.classList.toggle("open", on); body.hidden = !on; head.setAttribute("aria-expanded", on); if (on && onOpen) onOpen(); };
  head.addEventListener("click", e => { if (!e.target.closest("a,button,.copy")) set(body.hidden); });
  head.addEventListener("keydown", e => { if ((e.key === "Enter" || e.key === " ") && e.target === head) { e.preventDefault(); set(body.hidden); } });
  set(false);
  return set;
}
function caForm(form, path, extra) {
  const st = form.querySelector("[role=status]"), btn = form.querySelector("button[type=submit]");
  form.addEventListener("submit", async e => {
    e.preventDefault();
    if (!+form.days.value || +form.days.value < 1) return status(st, "Укажите целое число дней больше нуля", "error");
    const subjErr = form.querySelector("[data-subject-error]");
    subjErr.textContent = ""; form.subject.removeAttribute("aria-invalid");
    btn.disabled = true; status(st, "Создаём УЦ…");
    try {
      const ca = await call(path, Object.assign({subject: form.subject.value.trim(), days: +form.days.value, from: +form.from.value, closed: form.mode.value === "closed", algo: form.algo?.value}, typeof extra === "function" ? extra() : extra));
      location.assign("/" + ca.id + "#token=" + ca.admin);
    } catch (x) {
      btn.disabled = false;
      if (x.status === 400) {
        status(st, "Не удалось создать УЦ", "error");
        subjErr.textContent = x.message.charAt(0).toUpperCase() + x.message.slice(1); form.subject.setAttribute("aria-invalid", "true"); form.subject.focus();
      } else status(st, "Не удалось создать УЦ: " + (x.network ? "нет связи с сервером" : "ошибка сервера"), "error");
    }
  });
}
const b64url = b64 => b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const certview = b64 => "https://certview.deem.ru/#cert=" + b64url(b64);
const pem = b64 => "-----BEGIN CERTIFICATE-----\n" + b64.match(/.{1,64}/g).join("\n") + "\n-----END CERTIFICATE-----\n";
const when = s => s ? s.replace("T", " ").replace(/Z$/, " UTC").replace(/^(\d+)-(\d+)-(\d+)/, "$1.$2.$3") : "";
</script>{{end}}

{{define "index"}}{{template "head" "ТУЦ"}}
<div class="rows"><div class="item" id="create-root"><div class="head"><span class="name">Создать корневой УЦ</span></div>
<form class="body" id="root">
{{template "caform" .}}
<div class="row"><button class="primary" type="submit">Создать УЦ</button><span class="status" role="status"></span></div>
</form></div></div>
{{if .CAs}}<div class="rows" id="public-cas">{{range .CAs}}
<a class="item head" href="/{{.ID}}"><span class="name">{{if eq .Level 1}}Корневой УЦ{{else}}Подчинённый УЦ · уровень {{.Level}}{{end}}</span><span class="b blue">{{.Alg.Name}}</span><span class="id">{{slice .ID 0 8}}</span><span class="meta">{{time .Created}}</span></a>
{{end}}</div>{{else}}<p class="empty">Открытых УЦ пока нет</p>{{end}}
</main>{{template "common"}}
<script>openable($("#create-root")); caForm($("#root"), "/new", {});</script>
</body></html>{{end}}

{{define "sealed"}}{{template "head" "ТУЦ заблокирован"}}
<div class="card"><h2>Сервис заблокирован</h2>
<p>Дождитесь разблокирования оператором и обновите страницу.</p>
<p class="note">Оператор: доставьте мастер-секрет командой <code>tuc unseal</code> на сервере. Состояние: <code>sealed</code>.</p>
<div class="row"><button type="button" onclick="location.reload()">Обновить страницу</button></div></div>
</main></body></html>{{end}}

{{define "notfound"}}{{template "head" "УЦ не найден"}}
<div class="card"><h2>УЦ не найден</h2><p>Проверьте адрес. Возможно, УЦ удалён.</p>
<div class="row"><a class="button" href="/">Создать корневой УЦ</a></div></div>
</main></body></html>{{end}}

{{define "ca"}}{{template "head" .CN}}
<div id="access-error" class="banner error hidden" role="alert"></div>

<div class="card">
<p class="position"><span class="kind">{{if .Root}}Корневой УЦ{{else}}Подчинённый УЦ · уровень {{len .Chain}}{{end}}</span>{{with .Parent}}<a href="/{{.}}">Родительский УЦ</a>{{end}}</p>
<div class="title"><h2>{{.CN}}</h2>
<span class="b blue">{{.Alg.Name}}</span>
<span class="b mode {{if .Closed}}orange{{else}}green{{end}}" id="mode-pill"><span>{{if .Closed}}Выпуск по ссылке{{else}}Выпуск открыт{{end}}</span></span>
{{if .Revoked}}<span class="b red">Отозван</span>{{end}}
<span class="b grey{{if not .Disabled}} hidden{{end}}" id="disabled-pill">Отключён</span>
<span class="b solid hidden" id="pill-admin">Управление</span><span class="b blue hidden" id="pill-issue">Доступ по ссылке</span></div>
<p class="facts">{{if .Revoked}}отозван {{time .Revoked}} · {{end}}до {{time .NotAfter}} · SHA-1 <span class="copy" tabindex="0">{{.ID}}</span></p>
<div class="row"><a class="button" id="certview" target="_blank" rel="noopener noreferrer"><svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 1 L14 3 V8 Q14 12 8 15 Q2 12 2 8 V3 Z" fill="#012B6E"/><path d="M5 8 L7 10 L11 6" stroke="#fff" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>CertView</a></div>
</div>


<div class="banner warn hidden" id="save">
<p><b>Сохраните ссылку управления.</b> Полный доступ к этому УЦ. Храните её отдельно от ссылки выпуска.</p>
<div class="row"><button id="copy-admin">Скопировать ссылку управления</button><button id="saved">Ссылка сохранена</button></div>
</div>

<div class="rows" id="public-rows">
<div class="item" id="issue"><div class="head"><span class="name">Выпустить сертификат</span><span class="meta" id="issue-meta"></span><span class="meta" id="issue-term"></span><button class="hidden" id="issue-settings">Настроить срок</button></div>
<div class="body"><div id="issue-form">
<p id="way-note"></p>
<div class="controls" style="margin-top:8px">
<span class="seg" role="radiogroup" aria-label="Способ выпуска"><label><input type="radio" name="tool" value="pfx"> PFX</label><label><input type="radio" name="tool" value="openssl"> OpenSSL</label><label><input type="radio" name="tool" value="cryptopro"> КриптоПро</label></span>
<span class="seg" role="radiogroup" aria-label="Операционная система" id="os-seg">{{range .Commands}}{{if eq .Tool "cryptopro"}}<label><input type="radio" name="os" value="{{.ID}}"> {{.Title}}</label>{{end}}{{end}}</span>
<span class="seg" role="radiogroup" aria-label="Назначение"><label><input type="radio" name="purpose" value="plain" checked> Обычный</label><label><input type="radio" name="purpose" value="tls"> TLS</label></span>
<span class="seg" role="radiogroup" aria-label="Ответ УЦ" id="response-seg"><label><input type="radio" name="response" value="chain" checked> С цепочкой</label><label><input type="radio" name="response" value="cert"> Без цепочки</label></span>
</div>
<label class="field hidden" id="fqdn-field"><span>DNS-имя сервера</span><input type="text" id="fqdn" placeholder="test.example.org" autocomplete="off" aria-describedby="enroll-status"></label>
<div class="row hidden" id="pfx-fields"><label class="field"><span>Имя сертификата (CN)</span><input type="text" id="pfx-name" autocomplete="off" aria-describedby="enroll-status"></label><label class="field"><span>Алгоритм ключа</span><select id="pfx-algo">{{range .Algos}}<option value="{{.}}"{{if eq . $.Alg}} selected{{end}}>{{.Long}}</option>{{end}}</select></label><label class="field"><span>Пароль PFX</span><input type="text" id="pfx-password" autocomplete="off" aria-describedby="enroll-status"></label></div>
<div class="cmds" id="enroll-cmds">{{range $os := .Commands}}{{range .Enroll}}<pre data-os="{{$os.ID}}" data-tool="{{$os.Tool}}" data-purpose="{{.Purpose}}" data-response="{{.Response}}" class="enroll off" inert>{{.Script}}</pre>
{{end}}{{end}}</div>
<p class="note" id="enroll-note"></p>
<div class="row"><button class="primary" id="copy-enroll">Скопировать команду</button><button class="primary hidden" id="get-pfx">Выпустить и скачать PFX</button><span class="status" id="enroll-status" role="status"></span></div>
<div class="row hidden" id="pfx-import-open"><button id="open-import">Импорт имеющегося PFX</button></div>
<div class="hidden" id="pfx-import"><p style="margin-top:12px">Импорт PFX — в каталоге с файлом. <span id="pfx-pass-note"></span></p>
<div class="row"><label class="field"><span>Файл без .pfx</span><input type="text" id="imp-file" autocomplete="off"></label><label class="field"><span>CN — для КриптоПро</span><input type="text" id="imp-cn" autocomplete="off"></label><label class="field"><span>Пароль PFX</span><input type="text" id="imp-pass" autocomplete="off"></label></div>
<div class="controls" style="margin-top:8px"><span class="seg" role="radiogroup" aria-label="Импорт в"><label><input type="radio" name="imp" value="openssl"> OpenSSL</label><label><input type="radio" name="imp" value="cryptopro"> КриптоПро</label></span><span class="seg" role="radiogroup" aria-label="Операционная система" id="os3-seg">{{range .Commands}}{{if eq .Tool "cryptopro"}}<label><input type="radio" name="os3" value="{{.ID}}"> {{.Title}}</label>{{end}}{{end}}</span></div>
<div class="cmds">{{range .Commands}}{{if .Import}}<pre data-os="{{.ID}}" data-tool="{{.Tool}}" class="import off" inert>{{.Import}}</pre>
{{end}}{{end}}</div>
<p class="note" id="import-note"></p>
<div class="row"><button id="copy-import">Скопировать команду импорта</button></div></div>
</div>
<p class="hidden" id="closed-note">Для выпуска получите ссылку у владельца УЦ. Отозвать свой сертификат можно ниже без ссылки.</p>
</div></div>
<div class="item" id="verify"><div class="head"><span class="name">Проверить сертификат</span></div>
<div class="body">
<div class="controls"><span class="seg" role="radiogroup" aria-label="Где сертификат"><label><input type="radio" name="where" value="openssl"> В файлах OpenSSL</label><label><input type="radio" name="where" value="cryptopro"> В КриптоПро</label></span><span class="seg" role="radiogroup" aria-label="Операционная система" id="os4-seg">{{range .Commands}}{{if eq .Tool "cryptopro"}}<label><input type="radio" name="os4" value="{{.ID}}"> {{.Title}}</label>{{end}}{{end}}</span></div>
<p class="note" id="verify-note" style="margin-top:6px"></p>
<div class="cmds">{{range .Commands}}{{if .Verify}}<pre data-os="{{.ID}}" data-tool="{{.Tool}}" class="verify off" inert>{{.Verify}}</pre>
{{end}}{{end}}</div>
<div class="row"><button id="copy-verify">Скопировать команду проверки</button></div>
</div></div>

<div class="item hidden" id="issued"><div class="head"><span class="name">Сертификаты</span><span class="meta" id="issued-meta"></span></div>
<div class="body"><div class="rows" id="issued-list">
<div class="search"><input type="text" id="q" placeholder="Выпущенные сертификаты: имя, серийный номер или SHA-1"><button id="find">Найти</button><button id="refresh">Обновить</button></div>
<div id="certs"></div>
<p class="empty hidden" id="list-empty">Сертификатов пока нет.</p>
<p class="empty hidden" id="list-none">Ничего не найдено. <button id="reset">Сбросить поиск</button></p>
<div class="search hidden" id="more-row"><button id="more">Показать ещё</button></div>
<p class="empty status" id="list-status" role="status"></p>
</div></div></div>

{{if .CanChild}}<div class="item hidden" id="child-row"><div class="head"><span class="name">Создать подчинённый УЦ</span><span class="meta">уровень {{.ChildLevel}}</span></div>
<form class="body" id="child">
{{template "caform" .Child}}
<div class="row"><button class="primary" type="submit">Создать подчинённый УЦ</button><span class="status" role="status"></span></div>
</form></div>{{end}}
<div class="item" id="hier-row"><div class="head"><span class="name">Иерархия УЦ</span><span class="meta">уровень {{len .Chain}} · подчинённых УЦ: {{len .Children}}</span></div>
<div class="body"><div class="hier" id="hier">
<h3>Путь от корневого УЦ</h3>
<ol>{{range .Chain}}<li{{if .Current}} aria-current="page"{{end}}><span class="lvl">{{.Level}}</span><span class="cn">{{if .Current}}<b>{{.CN}}</b>{{else}}<a href="/{{.ID}}">{{.CN}}</a>{{end}}{{if .Revoked}} <span class="b red">Отозван</span>{{end}}</span><span class="id">{{slice .ID 0 8}}</span></li>{{end}}</ol>
{{with .Children}}<h3>Подчинённые УЦ</h3>
<ol>{{range .}}<li><span class="lvl">{{.Level}}</span><span class="cn"><a class="child" href="/{{.ID}}">{{.CN}}</a>{{if .Revoked}} <span class="b red">Отозван</span>{{end}}</span><span class="id">{{slice .ID 0 8}}</span></li>{{end}}</ol>{{else}}<h3>{{if .CanChild}}Подчинённых УЦ нет{{else}}Последний уровень иерархии: подчинённые УЦ не создаются{{end}}</h3>{{end}}
</div></div></div>
</div>

<div class="rows">
<div class="item" id="cert"><div class="head"><span class="name">Сертификат УЦ</span><span class="meta">до {{time .NotAfter}}</span></div>
<div class="body">
<table class="props">
<tr><td>Владелец</td><td>{{range .DN}}<div><span class="dn-key">{{index . 0}}=</span><span class="dn-val">{{index . 1}}</span></div>{{end}}</td></tr>
<tr><td>Издатель</td><td>{{.Issuer}}</td></tr>
<tr><td>Серийный номер</td><td class="copy" tabindex="0">{{.Serial}}</td></tr>
<tr><td>Действует</td><td>{{time .NotBefore}} — {{time .NotAfter}}</td></tr>
<tr><td>Алгоритм</td><td>{{.Alg.Long}}</td></tr>
</table>
<div class="row"><a class="button" href="{{.URL}}.crt">Скачать .crt</a><button id="copy-pem">Скопировать PEM</button><a class="button" href="{{.URL}}.crl">CRL</a></div>
</div></div>
<div class="item" id="revoke"><div class="head"><span class="name">Отозвать свой сертификат</span></div>
<div class="body">
<div class="controls"><span class="seg" role="radiogroup" aria-label="Где ключ"><label><input type="radio" name="tool2" value="pfx"> В PFX</label><label><input type="radio" name="tool2" value="openssl"> В файлах OpenSSL</label><label><input type="radio" name="tool2" value="cryptopro"> В КриптоПро</label></span><span class="seg" role="radiogroup" aria-label="Операционная система" id="os2-seg">{{range .Commands}}{{if eq .Tool "cryptopro"}}<label><input type="radio" name="os2" value="{{.ID}}"> {{.Title}}</label>{{end}}{{end}}</span></div>
<p class="note" id="revoke-note" style="margin-top:6px"></p>
<div class="cmds">{{range .Commands}}<pre data-os="{{.ID}}" data-tool="{{.Tool}}" class="revoke off" inert>{{.Revoke}}</pre>
{{end}}</div>
<div class="row"><button id="copy-revoke">Скопировать команду отзыва</button></div>
</div></div>

<div class="item hidden" id="access"><div class="head"><span class="name">Доступ к УЦ</span><span class="b green" id="access-pill">Ссылка сохранена</span></div>
<div class="body"><p>Ссылка выпуска: <span id="issue-link-note"></span></p>
<input type="text" readonly id="issue-link" style="margin-top:8px"><div class="row"><button id="copy-issue">Скопировать ссылку выпуска</button><button id="rotate-issue">Перевыпустить ссылку выпуска</button></div>
<p style="margin-top:12px">Ссылка управления: полный доступ к этому УЦ. Храните её отдельно от ссылки выпуска.</p>
<input type="text" readonly id="admin-link" style="margin-top:8px"><div class="row"><button id="copy-admin2">Скопировать ссылку управления</button><button id="rotate-admin">Перевыпустить ссылку управления</button><span role="status" id="rotate-status"></span></div></div></div>
<div class="item hidden" id="settings"><div class="head"><span class="name">Настройки УЦ</span><span class="b mode {{if .Closed}}orange{{else}}green{{end}}" id="settings-pill"><span>{{if .Closed}}Выпуск по ссылке{{else}}Выпуск открыт{{end}}</span></span></div>
<div class="body">
<div class="controls"><span class="seg" id="mode"><label><input type="radio" name="mode" value="open" {{if not .Closed}}checked{{end}}> Открытый</label><label><input type="radio" name="mode" value="closed" {{if .Closed}}checked{{end}}> По ссылке</label></span>
<span class="status" id="mode-status" role="status"></span></div>
<p class="note" style="margin-top:6px">Смена режима не меняет ссылку выпуска.</p>
<form id="issuance" style="margin-top:12px">
<p>Адреса проверки отзыва в новых сертификатах, в том числе сертификатах подчинённых УЦ. Уже выпущенные не изменятся.</p>
<div class="controls"><label><input type="checkbox" name="crl"> CRL — адрес списка отозванных сертификатов (CDP)</label><label><input type="checkbox" name="ocsp"> OCSP — адрес службы проверки отзыва (AIA)</label></div>
<p style="margin-top:12px">Начало и срок действия конечных сертификатов. Срок действия сертификата подчинённого УЦ задаётся при создании.</p>
<div class="row"><label class="field"><span>Начало действия, дней от выпуска</span><input type="number" name="from" min="-36500" max="36500" required></label><label class="field"><span>Срок, дней</span><input type="number" name="days" min="1" max="36500" required></label></div>
<p class="note">Отрицательное начало — задним числом. Срок обрезается по сроку УЦ.</p>
<div class="row"><button>Сохранить</button><span class="status" id="issuance-status" role="status"></span></div>
</form>
<div class="row" style="margin-top:12px"><button id="toggle-disabled">{{if .Disabled}}Включить УЦ{{else}}Отключить УЦ{{end}}</button><span class="status" id="disabled-status" role="status"></span></div>
<p class="note">Выпуск, публикация сертификата УЦ, CRL, OCSP и метки времени (TSP) отвечают 503. Управление и подчинённые УЦ не отключаются.</p>
{{if and (not .Root) (not .Revoked)}}<div class="row"><button class="danger" id="revoke-ca">Отозвать УЦ</button></div>{{end}}
{{if and (not .Root) (not .Revoked)}}<div class="hidden" id="revoke-confirm" style="margin-top:12px">
<p>{{.CN}} · {{.ID}}</p>
<p>Сертификат этого УЦ будет отозван родительским УЦ. Отзыв затрагивает цепочки всех выпущенных им сертификатов. Сам УЦ и его данные останутся. Отменить отзыв нельзя.</p>
<div class="row"><button type="button" id="revoke-cancel">Отмена</button><button class="danger" id="revoke-go">Отозвать безвозвратно</button><span class="status" id="revoke-status" role="status"></span></div>
</div>{{end}}
</div>
</div></div>
</div>
<div class="rows hidden" id="management-rows"></div>
</main>
{{template "common"}}
<script id="data" type="application/json">{{.JSON}}</script>
<script>
const ca = JSON.parse($("#data").textContent);
const self = "/" + ca.id;
let token = frag.get("token") || "";
const issue = frag.get("issue") || "";
for (const id of ["issue", "verify", "revoke", "cert", "hier-row"]) $("#public-rows").append($("#" + id));
for (const id of ["issued", "child-row", "access", "settings"]) { const row = $("#" + id); if (row) $("#management-rows").append(row); }
let issuance = ca.issuance;
function showTerm() { $("#issue-term").textContent = "срок " + new Intl.NumberFormat("ru", {style: "unit", unit: "day", unitDisplay: "long"}).format(issuance.days) + (issuance.from ? ", начало " + (issuance.from > 0 ? "+" : "") + issuance.from + " дн. от выпуска" : ""); }
showTerm();
// A pasted link of the same CA changes only the fragment: read it anew.
window.addEventListener("hashchange", () => location.reload());
let enroll = ca.url, closed = ca.closed;

// issuing: the issue form is shown, not the note of a CA that issues by link
let issuing = true;
// One visible command for the tool, the system of CryptoPro, purpose and response chosen
const gost = alg => alg.startsWith("gost");
const notes = {linux: "Нужен КриптоПро CSP. Ключ без пароля.", macos: "Нужен КриптоПро CSP. Ключ без пароля.",
  windows: "Нужен КриптоПро CSP. Для ключа используйте пустой пароль.",
  openssl: (ca.gostChain ? "Нужны curl и OpenSSL с gost-engine." : "Нужны openssl и curl.") + " Сертификат с цепочкой — в $NAME.crt, ключ без пароля — в $NAME.key.", pfx: ""};
const last = " В том же терминале отзовётся последний выпущенный сертификат, в другом сначала задайте NAME нужного сертификата.";
const revokeNotes = {cryptopro: "Нужен КриптоПро CSP." + last, openssl: "В каталоге с $NAME.crt и $NAME.key." + last,
  pfx: "В каталоге с файлом PFX. Для PFX, скачанного не на этой странице, задайте NAME — имя файла без .pfx — и PASS — его пароль. Для ключа ГОСТ нужен OpenSSL с gost-engine."};
const importNotes = {linux: "Нужен КриптоПро CSP. Ключ без пароля; установку корня в доверенные подтвердите.", macos: "Нужен КриптоПро CSP. Ключ без пароля; установку корня в доверенные подтвердите.",
  windows: "Нужен КриптоПро CSP. Используйте пустой пароль ключа; подтвердите установку корня в доверенные."};
// EST URL with the issue token, if any, as the HTTP Basic password
const est = () => { const u = new URL(ca.est), t = enroll.slice(ca.url.length + 1); if (t) { u.username = "tuc"; u.password = t; } return u.href; };
// The PFX downloaded last: the import and revoke commands name its file and password
// The PFX to import: the one downloaded last or one the fields name
let importing = false, pfxAlg = "";
const pfxFile = () => ({name: $("#imp-file").value.trim(), cn: $("#imp-cn").value.trim(), pass: $("#imp-pass").value});
const quote = (v, ps) => ps ? "'" + v.replace(/'/g, "''") + "'" : "'" + v.replace(/'/g, "'\\''") + "'";
const value = name => $("input[name=" + name + "]:checked").value;
// The tool, the system and the import target are remembered; a choice in the
// revoke block stays there.
function pick(name, value) {
  if (name !== "tool2") localStorage.setItem("tuc-" + name, value);
  for (const r of $$(name === "os" ? "input[name=os],input[name=os2],input[name=os3],input[name=os4]" : name === "tool" ? "input[name=tool],input[name=tool2]" : "input[name=" + name + "]")) r.checked = r.value === value;
  // the check and the revoke start where the issue, or the import of a PFX, puts the certificate
  if (name === "tool" || name === "imp") for (const r of $$("input[name=where]")) r.checked = r.value === (value === "cryptopro" ? "cryptopro" : "openssl");
  if (name === "imp") for (const r of $$("input[name=tool2]")) r.checked = r.value === (value === "cryptopro" ? "cryptopro" : "pfx");
  refresh();
}
const shown = sel => $$(sel).find(p => !p.classList.contains("off"));
// show displays one command of the tool group, which alone sizes the block
const show = (p, tool, on) => { p.classList.toggle("out", p.dataset.tool !== tool); p.classList.toggle("off", !on); p.inert = !on; };
const fqdnValid = fqdn => fqdn.length <= 253 && fqdn.split(".").every(label => label.length <= 63) && /^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$/.test(fqdn);
function refresh() {
  const tool = value("tool"), purpose = value("purpose"), os = value("os"), pfx = tool === "pfx", cp = tool === "cryptopro";
  const response = cp ? value("response") : "chain", id = cp ? os : tool;
  $("#issue-meta").textContent = !issuing ? "по ссылке" : {pfx: "PFX", openssl: "OpenSSL", cryptopro: "КриптоПро"}[tool] + (purpose === "tls" ? " · TLS" : "");
  for (const [sel, on] of [["#os-seg", cp], ["#response-seg", cp], ["#pfx-fields", pfx], ["#copy-enroll", !pfx], ["#get-pfx", pfx], ["#enroll-cmds", !pfx]]) $(sel).classList.toggle("hidden", !on);
  $("#way-note").textContent = pfx ? "Ключ создаёт УЦ и не хранит." : "Выполните в терминале.";
  for (const p of $$("pre.enroll")) show(p, tool, !pfx && p.dataset.os === id && p.dataset.purpose === purpose && p.dataset.response === response);
  $("#enroll-note").textContent = notes[id] + (response === "cert" ? " Корень не устанавливается: он должен быть уже в доверенных." : "");
  const tls = purpose === "tls", fqdn = $("#fqdn").value.trim();
  $("#fqdn-field").classList.toggle("hidden", !tls);
  // a CN of a TLS PFX starts with the server name if it fits in 64 characters
  const auto = "TUC-" + stamp();
  if (pfx && !nameEdited) $("#pfx-name").value = tls && fqdnValid(fqdn) && fqdn.length + 1 + auto.length <= 64 ? fqdn + "-" + auto : auto;
  for (const s of $$("[data-fqdn]")) s.textContent = fqdn || "<FQDN>";
  for (const s of $$("[data-tuc]")) s.textContent = ca.pub + enroll.slice(ca.url.length);
  for (const s of $$("[data-est]")) s.textContent = est();
  // Import of the PFX downloaded last
  const imp = value("imp"), impID = imp === "cryptopro" ? os : "openssl";
  $("#pfx-import").classList.toggle("hidden", !pfx || !importing);
  $("#pfx-import-open").classList.toggle("hidden", !pfx || importing);
  $("#os3-seg").classList.toggle("hidden", imp !== "cryptopro");
  for (const p of $$("pre.import")) show(p, imp, p.dataset.os === impID);
  const pf = pfxFile(), known = pf.name !== "";
  {
    $("#import-note").textContent = imp === "openssl" ? (ca.gostChain || (pfxAlg && gost(pfxAlg)) ? "Нужен OpenSSL с gost-engine." : !pfxAlg ? "Для ключа ГОСТ нужен OpenSSL с gost-engine." : "Нужен openssl.") + " Сертификат с цепочкой — в $NAME.crt, ключ без пароля — в $NAME.key." : importNotes[os];
  }
  for (const s of $$("[data-pfx]")) s.textContent = quote(pf[s.dataset.pfx], s.hasAttribute("data-ps"));
  for (const s of $$("[data-pfx-set]")) s.textContent = known ? "NAME=" + quote(pf.name) + "\nPASS=" + quote(pf.pass) : "NAME=${NAME:-}\nPASS=${PASS:-}";
  // Verify: where the certificate is
  const place = value("where");
  $("#os4-seg").classList.toggle("hidden", place !== "cryptopro");
  for (const p of $$("pre.verify")) show(p, place, p.dataset.os === (place === "cryptopro" ? os : "openssl"));
  $("#verify-note").textContent = place === "openssl" ?
    (ca.gostChain ? "Нужен OpenSSL с gost-engine. " : "") + "В каталоге с $NAME.crt." :
    "Нужен КриптоПро CSP.";
  // Revoke: where the key is
  const where = value("tool2"), whereID = where === "cryptopro" ? os : where;
  $("#os2-seg").classList.toggle("hidden", where !== "cryptopro");
  $("#revoke-note").textContent = revokeNotes[where];
  for (const p of $$("pre.revoke")) show(p, where, p.dataset.os === whereID);
  if (!tls || !fqdn || fqdnValid(fqdn)) invalid(null);
  else invalid($("#fqdn"), "Некорректное DNS-имя");
}
// invalid marks the field with the message, or clears the marks
function invalid(field, msg) {
  for (const f of ["#fqdn", "#pfx-name", "#pfx-password"]) $(f).removeAttribute("aria-invalid");
  if (field) field.setAttribute("aria-invalid", "true");
  status($("#enroll-status"), field ? msg : "", "error");
}
// check finds a field that stops the issue, marks and focuses it
function check(pfx) {
  const tls = value("purpose") === "tls", fqdn = $("#fqdn").value.trim();
  const bad = tls && !fqdn ? [$("#fqdn"), "Укажите DNS-имя сервера"] : tls && !fqdnValid(fqdn) ? [$("#fqdn"), "Некорректное DNS-имя"] :
    pfx && !$("#pfx-name").value.trim() ? [$("#pfx-name"), "Укажите имя"] : pfx && !$("#pfx-password").value ? [$("#pfx-password"), "Укажите пароль PFX"] : null;
  if (bad) { invalid(...bad); bad[0].focus(); }
  return !bad;
}
for (const r of $$("input[name=tool]")) r.addEventListener("change", () => pick("tool", r.value));
for (const r of $$("input[name=tool2]")) r.addEventListener("change", () => pick("tool2", r.value));
for (const r of $$("input[name=os],input[name=os2],input[name=os3],input[name=os4]")) r.addEventListener("change", () => pick("os", r.value));
for (const r of $$("input[name=where]")) r.addEventListener("change", refresh);
$("#open-import").onclick = () => { importing = true; pick("imp", value("imp")); $("#imp-file").focus(); };
for (const r of $$("input[name=imp]")) r.addEventListener("change", () => pick("imp", r.value));
for (const r of $$("input[name=purpose],input[name=response]")) r.addEventListener("change", refresh);
// A PFX is named like the commands name a certificate, at the time of the
// issue unless edited, under a random password
const stamp = () => new Date().toISOString().replace(/\D/g, "").replace(/^(\d{8})(\d{6}).*/, "$1-$2");
const newPassword = () => [...crypto.getRandomValues(new Uint8Array(12))].map(b => "abcdefghijkmnpqrstuvwxyz23456789"[b & 31]).join("");
let nameEdited = false;
$("#pfx-name").addEventListener("input", () => { nameEdited = true; });
$("#pfx-password").value = newPassword();
$("#get-pfx").onclick = async e => {
  const btn = e.target, st = $("#enroll-status");
  if (!nameEdited) refresh();
  if (!check(true)) return;
  const name = $("#pfx-name").value.trim(), pass = $("#pfx-password").value, alg = $("#pfx-algo").value;
  btn.disabled = true; status(st, "Выпускаем…");
  try {
    const r = await fetch(new URL(enroll).pathname + "/pfx", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({name, algo: alg,
      tls: value("purpose") === "tls", fqdn: $("#fqdn").value.trim(), password: pass})});
    if (r.status === 403 && issue) throw new Error("ссылка выпуска не подходит к этому УЦ. Попросите владельца прислать её заново");
    if (!r.ok) throw new Error((await r.text()).trim() || "ошибка " + r.status);
    // the file is named as the server names it
    const file = name.replace(/[^\p{L}\p{N}._-]+/gu, "_");
    const a = document.createElement("a");
    a.href = URL.createObjectURL(await r.blob()); a.download = file + ".pfx"; a.click(); URL.revokeObjectURL(a.href);
    $("#imp-file").value = file; $("#imp-cn").value = name; $("#imp-pass").value = pass; pfxAlg = alg; importing = true;
    $("#pfx-pass-note").textContent = "Сохраните пароль: после закрытия страницы его здесь не будет.";
    nameEdited = false; $("#pfx-password").value = newPassword();
    pick("imp", value("imp"));
    status(st, "Скачан " + file + ".pfx", "ok");
  } catch (x) { status(st, "Не удалось выпустить: " + x.message, "error"); }
  finally { btn.disabled = false; }
};
for (const id of ["#fqdn", "#pfx-password", "#imp-file", "#imp-cn", "#imp-pass"]) $(id).addEventListener("input", refresh);
// A remembered choice counts if the page still offers it
const remembered = (name, def) => { const v = localStorage.getItem("tuc-" + name); return $$("input[name=" + name + "]").some(r => r.value === v) ? v : def; };
for (const r of $$("input[name=imp]")) r.checked = r.value === remembered("imp", "openssl");
for (const r of $$("input[name=os],input[name=os2],input[name=os3],input[name=os4]")) r.checked = r.value === remembered("os", /Win/.test(navigator.platform) ? "windows" : /Mac/.test(navigator.platform) ? "macos" : "linux");
pick("tool", remembered("tool", "pfx"));
$("#copy-enroll").onclick = e => { if (check(false)) copyText(shown("pre.enroll").textContent, e.target, "Скопировать команду"); };
$("#copy-import").onclick = e => copyText(shown("pre.import").textContent, e.target, "Скопировать команду импорта");
$("#copy-verify").onclick = e => copyText(shown("pre.verify").textContent, e.target, "Скопировать команду проверки");
$("#copy-revoke").onclick = e => copyText(shown("pre.revoke").textContent, e.target, "Скопировать команду отзыва");

$("#copy-pem").onclick = e => copyText(pem(ca.der), e.target, "Скопировать PEM");
$("#certview").href = certview(ca.der);
for (const c of $$(".copy")) copyCell(c, c.textContent.trim());
openable($("#cert")); openable($("#revoke")); openable($("#hier-row")); openable($("#verify"));
// only the recipient of an issue link comes to issue: that row is open; otherwise all rows are closed
const openIssue = openable($("#issue"));
if (issue && !token) openIssue(true);

function showIssue(open) {
  issuing = open;
  $("#issue-form").classList.toggle("hidden", !open);
  $("#closed-note").classList.toggle("hidden", open);
  refresh();
}
showIssue(!closed);

// The page opened with the issue link of a CA that issues by link: the issue token from the fragment
if (issue && !token) {
  if (/^[a-z2-7]{32}$/.test(issue)) {
    enroll = ca.url + "/" + issue;
    $("#pill-issue").classList.remove("hidden"); showIssue(true);
  } else {
    showIssue(false); $("#closed-note").textContent = "Некорректная ссылка выпуска. Попросите владельца прислать её заново.";
  }
}
if (!token) document.documentElement.classList.remove("pending");

// Owner
let admin = null;
const adminLink = () => location.origin + self + "#token=" + admin.admin;
const issueLink = () => location.origin + self + "#issue=" + admin.issue;
const markSaved = on => { const p = $("#access-pill"); p.textContent = on ? "Ссылка сохранена" : "Ссылка не сохранена"; p.className = "b " + (on ? "green" : "orange"); };
function setMode(c) {
  for (const id of ["#mode-pill", "#settings-pill"]) { $(id).firstElementChild.textContent = c ? "Выпуск по ссылке" : "Выпуск открыт"; $(id).className = "b mode " + (c ? "orange" : "green"); }
  $("#issue-link").value = issueLink();
  $("#issue-link-note").textContent = c ? "даёт право выпуска в этом УЦ." : "выпуск открыт всем; ссылка не ограничивает доступ.";
}
async function checkAccess() {
  const b = $("#access-error"), retry = b.querySelector("button");
  if (retry) { retry.disabled = true; retry.textContent = "Проверяем…"; }
  try { admin = await call(self + "/admin", {token}); }
  catch (x) {
    b.classList.remove("hidden"); b.textContent = "";
    if (x.status === 403) b.textContent = "Ссылка управления не подходит к этому УЦ. Откройте сохранённую ссылку целиком.";
    else { b.append("Не удалось проверить доступ. "); const r = document.createElement("button"); r.textContent = "Повторить"; r.onclick = checkAccess; b.append(r); }
    return;
  }
  b.classList.add("hidden");
  for (const id of ["#pill-admin", "#child-row", "#issued", "#access", "#settings", "#management-rows", "#issue-settings"]) $(id)?.classList.remove("hidden");
  $("#admin-link").value = adminLink();
  const saved = localStorage.getItem("tuc-saved-own-" + ca.id) === admin.admin;
  $("#save").classList.toggle("hidden", saved); markSaved(saved);
  const f = $("#issuance");
  f.crl.checked = admin.issuance.crl; f.ocsp.checked = admin.issuance.ocsp; f.from.value = admin.issuance.from; f.days.value = admin.issuance.days;
  enroll = admin.enroll; setMode(admin.closed); showIssue(true); await list();
}
const reveal = () => document.documentElement.classList.remove("pending");
if (token) {
  checkAccess().finally(reveal);
  openable($("#access")); openable($("#settings")); openable($("#issued"));
  for (const id of ["#copy-admin", "#copy-admin2"]) $(id).onclick = e => copyText(adminLink(), e.target, "Скопировать ссылку управления");
  $("#saved").onclick = () => { localStorage.setItem("tuc-saved-own-" + ca.id, admin.admin); $("#save").classList.add("hidden"); markSaved(true); };
  $("#issue-settings").onclick = () => { if (!$("#settings").classList.contains("open")) $("#settings > .head").click(); $("#issuance input[name=days]").focus(); };
  for (const role of ["issue", "admin"]) $("#rotate-" + role).onclick = async e => {
    const button = e.target, st = $("#rotate-status"); button.disabled = true;
    try {
      const reply = await call(self + "/rotate", {token, role});
      admin[role] = reply.token;
      if (role === "admin") {
        token = reply.token; history.replaceState(null, "", adminLink());
        $("#admin-link").value = adminLink(); localStorage.removeItem("tuc-saved-own-" + ca.id);
        $("#save").classList.remove("hidden"); markSaved(false);
      } else { enroll = admin.closed ? ca.url + "/" + admin.issue : ca.url; setMode(admin.closed); refresh(); }
      status(st, "Старая ссылка больше не действует", "ok");
    } catch (x) { status(st, x.message, "error"); }
    finally { button.disabled = false; }
  };
  $("#copy-issue").onclick = e => copyText(issueLink(), e.target, "Скопировать ссылку выпуска");

  $("#issuance").onsubmit = async e => {
    e.preventDefault();
    const f = e.target, st = $("#issuance-status");
    status(st, "Сохраняем…");
    try {
      admin.issuance = await call(self + "/issuance", {token, issuance: {crl: f.crl.checked, ocsp: f.ocsp.checked, from: +f.from.value, days: +f.days.value}});
      issuance = admin.issuance; showTerm();
      status(st, "Сохранено", "ok");
    } catch (x) { status(st, x.network ? x.message : "Не удалось сохранить: " + x.message, "error"); }
  };

  for (const r of $$("#mode input")) r.addEventListener("change", async () => {
    const c = r.value === "closed", st = $("#mode-status");
    status(st, "Сохраняем…");
    try {
      await call(self + "/closed", {token, closed: c});
      admin.closed = c; admin.enroll = c ? ca.url + "/" + admin.issue : ca.url; enroll = admin.enroll;
      setMode(c); refresh(); status(st, "Сохранено", "ok");
    } catch (x) {
      for (const i of $$("#mode input")) i.checked = (i.value === "closed") === admin.closed;
      status(st, "Не удалось изменить режим выпуска", "error");
    }
  });

  // the new CA issues as this one does until its owner changes that
  if ($("#child-row")) openable($("#child-row"), () => {
    for (const i of $$("#child input[name=mode]")) i.checked = (i.value === "closed") === admin.closed;
  });
  if ($("#child")) caForm($("#child"), self + "/new", () => ({token}));

  // Disabling is undone by enabling; the pill tells every visitor
  let disabled = ca.disabled;
  $("#toggle-disabled").onclick = async e => {
    const st = $("#disabled-status"); e.target.disabled = true;
    try { await call(self + "/disabled", {token, disabled: !disabled}); disabled = !disabled; status(st, disabled ? "УЦ отключён" : "УЦ включён", "ok"); }
    catch (x) { status(st, "Не удалось: " + x.message, "error"); }
    e.target.disabled = false;
    e.target.textContent = disabled ? "Включить УЦ" : "Отключить УЦ";
    $("#disabled-pill").classList.toggle("hidden", !disabled);
  };
  if ($("#revoke-ca")) {
    $("#revoke-ca").onclick = () => $("#revoke-confirm").classList.remove("hidden");
    $("#revoke-cancel").onclick = () => $("#revoke-confirm").classList.add("hidden");
    $("#revoke-go").onclick = async e => {
      const st = $("#revoke-status"); e.target.disabled = true; status(st, "Отзываем…");
      try { await call(self + "/revoke", {token, self: true}); }
      catch (x) { status(st, "Не удалось отозвать УЦ: " + x.message, "error"); e.target.disabled = false; return; }
      location.reload();
    };
  }

  // Issued certificates: a row each, opening to its identifiers
  let q = "", offset = 0;
  const box = $("#certs");
  async function list(more) {
    const st = $("#list-status");
    let rows;
    try { rows = await call(self + "/list", {token, q, offset: more ? offset : 0}); }
    catch (x) {
      status(st, "Не удалось загрузить сертификаты. ", "error");
      const r = document.createElement("button"); r.textContent = "Повторить"; r.onclick = () => list(more); st.append(r);
      return;
    }
    // a refresh keeps the rows that were open and the focus
    const open = new Set($$("#certs .item.open").map(i => i.dataset.id)), fi = document.activeElement.closest?.("#certs .item");
    const focusables = item => [...item.querySelectorAll(".head,a,button,[tabindex]")];
    const focus = fi && [fi.dataset.id, focusables(fi).indexOf(document.activeElement)];
    if (!more) { box.textContent = ""; offset = 0; }
    offset += rows.length;
    status(st, "");
    $("#more-row").classList.toggle("hidden", rows.length < 100);
    $("#list-empty").classList.toggle("hidden", !(offset === 0 && q === ""));
    $("#list-none").classList.toggle("hidden", !(offset === 0 && q !== ""));
    for (const c of rows) row(c, open.has(c.ID));
    $("#issued-meta").textContent = (q ? "найдено " : "") + offset + (rows.length === 100 ? "+" : "");
    const item = !more && focus && box.querySelector("[data-id=\"" + focus[0] + "\"]");
    if (item) (focusables(item)[focus[1]] || item.querySelector(".head")).focus({preventScroll: true});
  }
  window.list = list;
  function el(tag, text, cls) { const e = document.createElement(tag); if (text) e.textContent = text; if (cls) e.className = cls; return e; }
  function row(c, open) {
    const item = el("div", null, "item cert"), head = el("div", null, "head"), body = el("div", null, "body");
    item.dataset.id = c.ID; item.append(head, body); box.append(item);
    const parts = c.Subject.split(", ");
    const cn = (parts.find(p => p.startsWith("CN=")) || parts[0]).replace(/^CN=/, "");
    const name = el(c.CA && c.Live ? "a" : "span", cn, "name");
    if (c.CA && c.Live) name.href = "/" + c.ID;
    head.append(name);
    if (c.CA) head.append(el("span", "Подчинённый УЦ", "b blue"));
    const expired = new Date(c.NotAfter) < new Date(), early = new Date(c.NotBefore) > new Date();
    const state = el("span", c.Revoked ? "Отозван" : expired ? "Срок истёк" : early ? "Ещё не действует" : "Действует", "b " + (c.Revoked ? "red" : expired || early ? "grey" : "green"));
    head.append(state, el("span", "до " + when(c.NotAfter), "meta"));
    const act = el("span", null, "actions"); head.append(act);
    const dl = el("a", "Скачать", "button"); dl.href = self + "/cert/" + c.ID + ".crt"; act.append(dl);
    const cv = el("a", "CertView", "button"); cv.href = certview(c.DER); cv.target = "_blank"; cv.rel = "noopener noreferrer"; act.append(cv);

    const t = el("table", null, "props"); body.append(t);
    for (const [k, v, copy] of [["Владелец", c.Subject], ["Выдан", when(c.Created)], ["Действует", when(c.NotBefore) + " — " + when(c.NotAfter)], ["Серийный номер", c.Serial, true], ["SHA-1", c.ID, true]].concat(c.Revoked ? [["Отозван", when(c.Revoked)]] : [])) {
      const tr = t.insertRow(); tr.insertCell().textContent = k; const td = tr.insertCell(); td.textContent = v;
      if (copy) { td.className = "copy"; td.tabIndex = 0; copyCell(td, v); }
    }
    if (!c.Revoked) {
      const r = el("div", null, "row"), rv = el("button", "Отозвать", "danger"); r.append(rv); body.append(r);
      rv.onclick = () => {
        r.classList.add("hidden");
        const conf = el("div", null, "row"), st = el("span", null, "status"), go = el("button", "Отозвать сертификат", "danger"), no = el("button", "Отмена");
        conf.append(el("span", "Отменить отзыв нельзя."), go, no, st); body.append(conf);
        no.onclick = () => { conf.remove(); r.classList.remove("hidden"); };
        go.onclick = async () => {
          go.disabled = true; status(st, "Отзываем…");
          try { await call(self + "/revoke", {token, cert: c.ID}); }
          catch (x) { status(st, "Не удалось отозвать: " + x.message, "error"); go.disabled = false; return; }
          state.textContent = "Отозван"; state.className = "b red"; conf.remove(); r.remove();
          const h = $$("#hier a.child").find(a => new URL(a.href).pathname === "/" + c.ID);
          if (h && !h.parentElement.querySelector(".b.red")) h.after(" ", el("span", "Отозван", "b red"));
        };
      };
    }
    openable(item)(open);
  }
  $("#find").onclick = () => { q = $("#q").value.trim(); list(); };
  $("#q").addEventListener("keydown", e => { if (e.key === "Enter") { q = $("#q").value.trim(); list(); } });
  $("#refresh").onclick = () => list();
  $("#reset").onclick = () => { $("#q").value = ""; q = ""; list(); };
  $("#more").onclick = () => list(true);
  document.addEventListener("visibilitychange", () => document.visibilityState === "visible" && admin && list());
}
</script>
</body></html>{{end}}
`))

func (s *Service) indexPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	cas, err := s.st.publicCAs()
	if err != nil {
		log.Printf("index page: %v", err)
		http.Error(w, "Не удалось загрузить список УЦ", http.StatusInternalServerError)
		return
	}
	data := map[string]any{"CAs": cas, "Subject": testName(1), "Algos": algos, "Alg": algos[0]}
	if err := pages.ExecuteTemplate(w, "index", data); err != nil {
		log.Printf("index page: %v", err)
	}
}

type chainNode struct {
	ID, CN                 string
	Level                  int // 1 for a root
	Root, Current, Revoked bool
}

func (s *Service) caPage(w http.ResponseWriter, r *http.Request) {
	n, err := s.open(r.PathValue("id"))
	if err != nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		pages.ExecuteTemplate(w, "notfound", nil)
		return
	}
	defer n.Close()
	gostChain := false
	var chain []chainNode
	for c := n; c != nil; c = c.parent {
		gostChain = gostChain || c.alg.Family() == "gost"
		node := chainNode{ID: c.id, CN: c.cert.Subject.CommonName, Root: c.parent == nil, Current: c == n}
		if c.parent != nil {
			at, _ := s.st.revokedAt(c.parent.id, c.id)
			node.Revoked = at != nil
		}
		chain = append([]chainNode{node}, chain...)
	}
	for i := range chain {
		chain[i].Level = i + 1
	}
	parent := ""
	var revoked *time.Time
	if n.parent != nil {
		parent = n.parent.id
		revoked, _ = s.st.revokedAt(n.parent.id, n.id)
	}
	rows, err := s.st.children(n.id)
	if err != nil {
		log.Printf("CA page: %v", err)
	}
	var children []chainNode
	for _, c := range rows {
		cn := c.id
		if x, err := x509.ParseCertificate(c.cert); err == nil {
			cn = x.Subject.CommonName
		}
		children = append(children, chainNode{ID: c.id, CN: cn, Level: len(chain) + 1, Revoked: c.revoked})
	}
	data := map[string]any{
		"Revoked": revoked, "Alg": n.alg, "Algos": algos,
		"ID": n.id, "CN": n.cert.Subject.CommonName, "Root": n.parent == nil, "Closed": n.closed, "Disabled": n.disabled,
		"DN": nameParts(n.cert.RawSubject), "Issuer": nameString(n.cert.RawIssuer), "Serial": hexSerial(n.cert.SerialNumber),
		"NotBefore": n.cert.NotBefore, "NotAfter": n.cert.NotAfter,
		"URL": s.caURL(n.id), "Chain": chain, "Parent": parent, "Children": children, "CanChild": len(chain) < maxLevel, "ChildLevel": len(chain) + 1,
		"Commands": commands(s.publicationURL(n.id), s.estURL(n.id), s.publicationURL(chain[0].ID), n.alg),
		"Child": map[string]any{"Subject": testName(len(chain) + 1), "Closed": n.closed, "Child": true,
			"Algos": algos, "Alg": n.alg},
		"JSON": map[string]any{"id": n.id, "url": s.caURL(n.id), "pub": s.publicationURL(n.id), "est": s.estURL(n.id), "alg": n.alg, "issuance": n.iss, "gostChain": gostChain, "parent": parent, "closed": n.closed, "disabled": n.disabled,
			"der": base64.StdEncoding.EncodeToString(n.der)},
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := pages.ExecuteTemplate(w, "ca", data); err != nil {
		log.Printf("CA page: %v", err)
	}
}

// testName is the name a new CA form starts with, made distinct by the time.
func testName(level int) string {
	return "CN=Тестовый УЦ (уровень " + fmt.Sprint(level) + ") (" + time.Now().UTC().Format("2006.01.02 15:04:05") + " UTC),O=ТУЦ,C=RU"
}
