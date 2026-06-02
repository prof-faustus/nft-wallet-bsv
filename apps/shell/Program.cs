// WS7 shell — the REAL native Windows (WPF) app. This is the genuine
// window, not a web page. It is fully MENU-DRIVEN: the user chooses the
// crypto-shred scheme from a menu populated by the sidecar, types every
// amount (funding, dust, fee, price, blocks) with NO pre-filled defaults,
// and clicks each step explicitly. Nothing is auto-driven; the sidecar
// enforces that every required value is supplied (a blank field yields the
// sidecar's "required" error, shown in the log).
//
// Honesty surface (unchanged): PENDING (amber) vs CONFIRMED (green) exactly
// as the sidecar reports; deletion shown as a CLAIM label that never says
// "verified". The shell holds NO keys; every step goes through the sidecar.
using System;
using System.Globalization;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;

namespace NftWalletBsv.Shell
{
    public static class Program
    {
        [STAThread]
        public static void Main()
        {
            var app = new Application();
            app.Run(new MainWindow());
        }
    }

    public sealed class MainWindow : Window
    {
        private readonly SidecarClient _status;
        private readonly SidecarV2 _v2;

        private readonly ComboBox _scheme = new ComboBox { Width = 200 };
        private readonly TextBox _aliceLabel = Tb("seller");
        private readonly TextBox _bobLabel = Tb("buyer");
        private readonly TextBox _aliceFund = Tb("");
        private readonly TextBox _bobFund = Tb("");
        private readonly TextBox _payload = Tb("");
        private readonly TextBox _dust = Tb("");
        private readonly TextBox _mintFee = Tb("");
        private readonly TextBox _price = Tb("");
        private readonly TextBox _swapFee = Tb("");
        private readonly TextBox _blocks = Tb("");

        private readonly TextBlock _statusText = new TextBlock { FontSize = 16, TextWrapping = TextWrapping.Wrap };
        private readonly TextBlock _deletion = new TextBlock { TextWrapping = TextWrapping.Wrap, Foreground = Brushes.DimGray };
        private readonly TextBox _log = new TextBox
        {
            IsReadOnly = true, AcceptsReturn = true, TextWrapping = TextWrapping.Wrap,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Height = 220,
            FontFamily = new FontFamily("Consolas"), Background = Brushes.Black, Foreground = Brushes.LightGreen,
        };

        public MainWindow()
        {
            Title = "nft-wallet-bsv — menu-driven (BSV only; non-custodial; the shell holds NO keys)";
            Width = 940; Height = 900;

            string? baseUrl = Environment.GetEnvironmentVariable("NFTBSV_SIDECAR");
            if (string.IsNullOrEmpty(baseUrl)) baseUrl = "http://127.0.0.1:8090";
            _status = new SidecarClient(baseUrl);
            _v2 = new SidecarV2(baseUrl);

            var root = new StackPanel { Margin = new Thickness(16) };
            root.Children.Add(Bold("Every choice is yours — pick a scheme, type every amount, run each step. Nothing is preselected."));

            // 1 — scheme + reset
            var bReset = Btn("1 · Start session with this scheme");
            bReset.Click += async (s, e) => await Step(bReset, "/v2/reset", new { scheme = SelectedScheme() });
            root.Children.Add(Row("Crypto-shred scheme:", _scheme, bReset));

            // 2 — keys
            var bKeys = Btn("2 · Create keys");
            bKeys.Click += async (s, e) => await Step(bKeys, "/v2/keys", new { alice_label = _aliceLabel.Text, bob_label = _bobLabel.Text });
            root.Children.Add(Row("Seller label:", _aliceLabel, Lbl("Buyer label:"), _bobLabel, bKeys));

            // 3 — funding (user-controlled amounts)
            var bFundA = Btn("3a · Fund seller");
            bFundA.Click += async (s, e) => await Step(bFundA, "/v2/fund", new { who = "alice", sats = Num(_aliceFund) });
            var bFundB = Btn("3b · Fund buyer");
            bFundB.Click += async (s, e) => await Step(bFundB, "/v2/fund", new { who = "bob", sats = Num(_bobFund) });
            root.Children.Add(Row("Seller funding (sats):", _aliceFund, bFundA));
            root.Children.Add(Row("Buyer funding (sats):", _bobFund, bFundB));

            // 4 — mint (seals payload with the chosen scheme)
            var bMint = Btn("4 · Mint + seal payload");
            bMint.Click += async (s, e) => await Step(bMint, "/v2/mint", new { payload_text = _payload.Text, dust_sats = Num(_dust), fee_sats = Num(_mintFee) });
            root.Children.Add(Row("NFT payload:", _payload));
            root.Children.Add(Row("Dust (sats):", _dust, Lbl("Mint fee (sats):"), _mintFee, bMint));

            // 5 — deliver (buyer opens + verifies)
            var bDeliver = Btn("5 · Buyer decrypts + verifies");
            bDeliver.Click += async (s, e) => await Step(bDeliver, "/v2/deliver", new { });
            root.Children.Add(Row("", bDeliver));

            // 6 — swap
            var bSwap = Btn("6 · Co-sign + broadcast swap");
            bSwap.Click += async (s, e) => await Step(bSwap, "/v2/swap", new { price_sats = Num(_price), fee_sats = Num(_swapFee) });
            root.Children.Add(Row("Price to seller (sats):", _price, Lbl("Swap fee (sats):"), _swapFee, bSwap));

            // 7 — confirm
            var bConfirm = Btn("7 · Confirm (mine N blocks)");
            bConfirm.Click += async (s, e) => await Step(bConfirm, "/v2/confirm", new { blocks = NumInt(_blocks) });
            root.Children.Add(Row("Blocks to mine:", _blocks, bConfirm));

            // 8 — shred, 9 — attest
            var bShred = Btn("8 · Seller shreds key material");
            bShred.Click += async (s, e) => await Step(bShred, "/v2/shred", new { });
            var bAttest = Btn("9 · Seller attests deletion (a CLAIM)");
            bAttest.Click += async (s, e) => await Step(bAttest, "/v2/attest", new { });
            root.Children.Add(Row("", bShred, bAttest));

            root.Children.Add(new Separator());
            root.Children.Add(Bold("Exchange status"));
            root.Children.Add(_statusText);
            root.Children.Add(Bold("Deletion"));
            root.Children.Add(_deletion);
            root.Children.Add(Bold("Live log (real txids when run against a node)"));
            root.Children.Add(_log);

            Content = new ScrollViewer { Content = root, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };

            Loaded += async (s, e) => await LoadOptionsAsync();
            var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            timer.Tick += async (s, e) => await RefreshAsync();
            timer.Start();
        }

        private string SelectedScheme() => _scheme.SelectedItem as string ?? "";

        private async Task LoadOptionsAsync()
        {
            try
            {
                V2Options? o = await _v2.GetOptionsAsync();
                _scheme.Items.Clear();
                if (o?.data?.schemes != null)
                    foreach (var name in o.data.schemes) _scheme.Items.Add(name);
                // No default selection — the user MUST choose (owner rule).
                _scheme.SelectedIndex = -1;
                Append("Loaded " + (_scheme.Items.Count) + " scheme(s) from the sidecar. Choose one to begin.");
            }
            catch (Exception ex) { Append("Could not load options (is the sidecar running?): " + ex.Message); }
        }

        private async Task Step(Button self, string path, object body)
        {
            self.IsEnabled = false;
            try
            {
                V2Resp? r = await _v2.PostAsync(path, body);
                if (r != null)
                {
                    if (r.log != null) { _log.Text = string.Join("\n", r.log); _log.ScrollToEnd(); }
                    if (!r.ok) MessageBox.Show(r.error ?? "step failed", "Step failed — choose/enter the required value");
                }
            }
            catch (Exception ex) { MessageBox.Show(ex.Message, "Error"); }
            finally { self.IsEnabled = true; }
            await RefreshAsync();
        }

        private async Task RefreshAsync()
        {
            try
            {
                StatusDto? st = await _status.GetStatusAsync();
                if (st == null) return;
                _statusText.Text = st.label;
                _statusText.Foreground = st.failed ? Brushes.Firebrick
                    : st.success ? Brushes.DarkGreen
                    : Brushes.DarkGoldenrod;
                _deletion.Text = st.deletion_label;
            }
            catch (Exception ex)
            {
                _statusText.Text = "sidecar unreachable: " + ex.Message;
                _statusText.Foreground = Brushes.Gray;
            }
        }

        private void Append(string line) { _log.Text += (string.IsNullOrEmpty(_log.Text) ? "" : "\n") + line; _log.ScrollToEnd(); }

        // Num returns the parsed amount, or null when the field is blank/invalid
        // so the sidecar enforces the "required" rule (no client-side default).
        private static long? Num(TextBox tb)
        {
            if (long.TryParse(tb.Text.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out long v)) return v;
            return null;
        }
        private static int? NumInt(TextBox tb)
        {
            if (int.TryParse(tb.Text.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out int v)) return v;
            return null;
        }

        private static TextBox Tb(string initial) => new TextBox { Width = 150, Text = initial, Margin = new Thickness(0, 0, 10, 0) };
        private static Button Btn(string content) => new Button { Content = content, Margin = new Thickness(0, 0, 8, 0), Padding = new Thickness(8, 4, 8, 4) };
        private static TextBlock Lbl(string text) => new TextBlock { Text = text, Margin = new Thickness(0, 0, 6, 0), VerticalAlignment = VerticalAlignment.Center };
        private static TextBlock Bold(string text) => new TextBlock { Text = text, FontWeight = FontWeights.Bold, Margin = new Thickness(0, 10, 0, 4), TextWrapping = TextWrapping.Wrap };

        private static StackPanel Row(string labelText, params UIElement[] controls)
        {
            var p = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 3, 0, 3) };
            if (!string.IsNullOrEmpty(labelText))
                p.Children.Add(new TextBlock { Text = labelText, Width = 150, VerticalAlignment = VerticalAlignment.Center });
            foreach (var c in controls) p.Children.Add(c);
            return p;
        }
    }
}
