// Verschlüsselt die App-Seite (AES-GCM, PBKDF2) für GitHub Pages.
// Aufruf: APP_PASSWORD='…' node build.mjs <Bewerbungen.html> <docs/index.html>
import {readFileSync,writeFileSync} from 'node:fs';
import {webcrypto as c} from 'node:crypto';
const [,, src, out]=process.argv, pw=process.env.APP_PASSWORD;
if(!src||!out||!pw){console.error('Nutzung: APP_PASSWORD=… node build.mjs in.html out.html');process.exit(1)}
const ITER=600000, enc=new TextEncoder();
const salt=c.getRandomValues(new Uint8Array(16)), iv=c.getRandomValues(new Uint8Array(12));
const km=await c.subtle.importKey('raw',enc.encode(pw),'PBKDF2',false,['deriveKey']);
const key=await c.subtle.deriveKey({name:'PBKDF2',salt,iterations:ITER,hash:'SHA-256'},km,{name:'AES-GCM',length:256},false,['encrypt']);
const ct=new Uint8Array(await c.subtle.encrypt({name:'AES-GCM',iv},key,enc.encode(readFileSync(src,'utf8'))));
const b=u=>Buffer.from(u).toString('base64');
const payload=JSON.stringify({s:b(salt),i:b(iv),n:ITER,d:b(ct)});
const icon="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 192 192'%3E%3Crect width='192' height='192' rx='40' fill='%23005580'/%3E%3Cpath d='M52 100l30 30 60-70' fill='none' stroke='white' stroke-width='18' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E";
const html=`<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><title>Bewerbungen</title><meta name="robots" content="noindex,nofollow"><meta name="theme-color" content="#005580"><meta name="apple-mobile-web-app-capable" content="yes"><meta name="mobile-web-app-capable" content="yes"><meta name="apple-mobile-web-app-title" content="Bewerbungen"><link rel="icon" href="${icon}"><link rel="apple-touch-icon" href="${icon}">
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;font:16px system-ui,sans-serif;background:#f3f5f8;color:#17212b}@media(prefers-color-scheme:dark){body{background:#10161d;color:#e6ecf2}}form{width:min(320px,90vw);display:flex;flex-direction:column;gap:12px}input,button{font:inherit;padding:12px;border-radius:10px;border:1px solid #8886}button{background:#005580;color:#fff;border:0;font-weight:600}label{display:flex;gap:8px;align-items:center;font-size:.9rem}#m{min-height:1.2em;color:#b4461f;font-size:.9rem}</style></head><body>
<form id="f"><h1 style="margin:0;font-size:1.4rem">Bewerbungen</h1><input id="p" type="password" placeholder="Passwort" autocomplete="current-password" autofocus><label><input id="r" type="checkbox" style="width:auto"> Auf diesem Gerät merken</label><button>Öffnen</button><div id="m" aria-live="polite"></div></form>
<script id="payload" type="application/json">${payload}</script>
<script>
const P=JSON.parse(document.getElementById("payload").textContent),u=s=>Uint8Array.from(atob(s),x=>x.charCodeAt(0));
async function open_(pw){const km=await crypto.subtle.importKey("raw",new TextEncoder().encode(pw),"PBKDF2",false,["deriveKey"]);
 const k=await crypto.subtle.deriveKey({name:"PBKDF2",salt:u(P.s),iterations:P.n,hash:"SHA-256"},km,{name:"AES-GCM",length:256},false,["decrypt"]);
 return new TextDecoder().decode(await crypto.subtle.decrypt({name:"AES-GCM",iv:u(P.i)},k,u(P.d)))}
async function go(pw,remember){const m=document.getElementById("m");m.style.color="";m.textContent="Entschlüssele …";
 try{const h=await open_(pw);if(remember){try{localStorage.setItem("bw-pw",pw)}catch(e){}}document.open();document.write(h);document.close()}
 catch(e){m.style.color="#b4461f";m.textContent="Falsches Passwort.";try{localStorage.removeItem("bw-pw")}catch(e2){}}}
document.getElementById("f").addEventListener("submit",e=>{e.preventDefault();go(document.getElementById("p").value,document.getElementById("r").checked)});
try{const s=localStorage.getItem("bw-pw");if(s)go(s,true)}catch(e){}
</script></body></html>`;
writeFileSync(out,html);console.log('OK',out,html.length);
