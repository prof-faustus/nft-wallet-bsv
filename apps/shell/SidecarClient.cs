// SidecarClient — the shell's ONLY link to the Go sidecar (localhost
// HTTP, OD-2). The shell asks the sidecar for status/addresses/swap
// review; it never receives or handles private keys (non-custodial,
// docs/06 WS7).
using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace NftWalletBsv.Shell
{
    // Mirror of the sidecar's /status JSON (internal/sidecar.statusResp).
    public sealed class StatusDto
    {
        public string engine_state { get; set; } = "";
        public string label { get; set; } = "";
        public bool success { get; set; }
        public bool pending { get; set; }
        public bool failed { get; set; }
        public string deletion_label { get; set; } = "";
    }

    public sealed class SidecarClient
    {
        private readonly HttpClient _http = new HttpClient();
        private readonly string _base;

        public SidecarClient(string baseUrl)
        {
            _base = baseUrl.TrimEnd('/');
        }

        public async Task<StatusDto?> GetStatusAsync()
        {
            string s = await _http.GetStringAsync(_base + "/status");
            return JsonSerializer.Deserialize<StatusDto>(s);
        }

        public async Task<string> GetAddressAsync(string label)
        {
            // Returns an address only — never key material.
            return await _http.GetStringAsync(_base + "/address?label=" + Uri.EscapeDataString(label));
        }

        // ReviewSwapAsync posts the assembled swap + expected terms; the
        // sidecar returns the EXACT terms to display before signing, or a
        // rejection reason (docs/02 §2.5 step 2). The shell must NOT enable
        // "Sign & Confirm" unless this returns ok.
        public async Task<string> ReviewSwapAsync(string jsonBody)
        {
            var content = new StringContent(jsonBody, Encoding.UTF8, "application/json");
            HttpResponseMessage resp = await _http.PostAsync(_base + "/swap/review", content);
            return await resp.Content.ReadAsStringAsync();
        }

        // PostActionAsync triggers a LIVE on-chain step in the sidecar
        // (/action/setup-mint, /action/swap, /action/confirm,
        // /action/attest) and returns the parsed {ok, error, log}.
        public async Task<ActionResp?> PostActionAsync(string path)
        {
            HttpResponseMessage resp = await _http.PostAsync(_base + path, new StringContent("", Encoding.UTF8, "application/json"));
            string s = await resp.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<ActionResp>(s);
        }
    }

    public sealed class ActionResp
    {
        public bool ok { get; set; }
        public string? error { get; set; }
        public string[]? log { get; set; }
    }

    // ---- v2 menu-driven API ------------------------------------------------

    // V2Resp mirrors internal/sidecar.v2Resp. `data` is left as raw JSON since
    // the shell only needs ok/error/log for its menu flow.
    public sealed class V2Resp
    {
        public bool ok { get; set; }
        public string? error { get; set; }
        public string[]? log { get; set; }
    }

    public sealed class V2Options
    {
        public bool ok { get; set; }
        public OptionsData? data { get; set; }
        public sealed class OptionsData
        {
            public string[]? schemes { get; set; }
        }
    }

    public partial class SidecarV2
    {
        private readonly HttpClient _http = new HttpClient();
        private readonly string _base;
        public SidecarV2(string baseUrl) { _base = baseUrl.TrimEnd('/'); }

        // GetOptionsAsync fetches the menus (e.g. the crypto-shred scheme list)
        // so the UI never hard-codes the choices.
        public async Task<V2Options?> GetOptionsAsync()
        {
            HttpResponseMessage resp = await _http.PostAsync(_base + "/v2/options", new StringContent("{}", Encoding.UTF8, "application/json"));
            return JsonSerializer.Deserialize<V2Options>(await resp.Content.ReadAsStringAsync());
        }

        // PostAsync sends a JSON body to a /v2 step and returns {ok,error,log}.
        public async Task<V2Resp?> PostAsync(string path, object body)
        {
            string json = JsonSerializer.Serialize(body);
            HttpResponseMessage resp = await _http.PostAsync(_base + path, new StringContent(json, Encoding.UTF8, "application/json"));
            return JsonSerializer.Deserialize<V2Resp>(await resp.Content.ReadAsStringAsync());
        }
    }
}
