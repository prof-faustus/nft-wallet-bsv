// A minimal localhost web control panel served by the sidecar, so an
// operator can drive the real regtest exchange interactively from their
// own browser (the native WPF shell is the docs/OD-2 surface, but a
// browser page is reliably interactive regardless of how the process was
// launched). It calls the same /action/* + /status endpoints and renders
// the SAME honest state (pending amber / confirmed green; deletion a
// CLAIM, never "verified"). The browser holds NO keys.
package sidecar

import "net/http"

func (s *Server) webHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(controlPanelHTML))
}

const controlPanelHTML = `<!doctype html>
<html><head><meta charset="utf-8"><title>nft-wallet-bsv — Stage 1</title>
<style>
 body{font-family:'Segoe UI',Arial,sans-serif;margin:24px;max-width:920px;color:#222}
 .banner{font-size:18px;padding:12px;border-radius:8px;margin:10px 0;font-weight:600}
 .pending{background:#fff3cd;color:#856404}.ok{background:#d4edda;color:#155724}
 .fail{background:#f8d7da;color:#721c24}.idle{background:#e2e3e5;color:#383d41}
 button{margin:4px 6px 4px 0;padding:9px 14px;font-size:14px;cursor:pointer}
 button:disabled{cursor:not-allowed;opacity:.5}
 #log{background:#0b0b0b;color:#7CFC00;font-family:Consolas,monospace;font-size:13px;
      padding:12px;height:260px;overflow:auto;white-space:pre-wrap;border-radius:8px}
 .muted{color:#666;margin:6px 0}
</style></head><body>
<h2>nft-wallet-bsv — Stage 1 <span class="muted">(BSV only; non-custodial; the browser holds NO keys)</span></h2>
<p>Drive a <b>real</b> regtest exchange — each step runs on-chain:</p>
<div>
 <button id="b1" onclick="act('/action/setup-mint',this,'b2')">1 · Setup + Mint NFT</button>
 <button id="b2" onclick="act('/action/swap',this,'b3')" disabled>2 · Sign &amp; broadcast swap</button>
 <button id="b3" onclick="act('/action/confirm',this,'b4')" disabled>3 · Confirm (mine block)</button>
 <button id="b4" onclick="act('/action/attest',this,null)" disabled>4 · Attest deletion</button>
</div>
<div id="banner" class="banner idle">connecting…</div>
<div id="deletion" class="muted"></div>
<h3>Live log (real txids)</h3>
<div id="log"></div>
<script>
async function refresh(){
  try{
    const s = await (await fetch('/status')).json();
    const b = document.getElementById('banner');
    b.textContent = s.label;
    b.className = 'banner ' + (s.failed?'fail':s.success?'ok':(s.pending?'pending':'idle'));
    document.getElementById('deletion').textContent = s.deletion_label;
  }catch(e){}
}
async function act(path, btn, next){
  btn.disabled = true;
  try{
    const j = await (await fetch(path, {method:'POST'})).json();
    const log = document.getElementById('log');
    log.textContent = (j.log||[]).join('\n');
    log.scrollTop = log.scrollHeight;
    if(j.ok){ if(next) document.getElementById(next).disabled = false; }
    else { btn.disabled = false; alert(j.error || 'step failed'); }
  }catch(e){ btn.disabled = false; alert(e); }
  refresh();
}
setInterval(refresh, 1000); refresh();
</script></body></html>`
