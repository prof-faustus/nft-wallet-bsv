// WS7 shell entry point. An interactive, code-only WPF app that drives a
// REAL regtest exchange through the Go sidecar and renders the sidecar's
// HONEST state. It never overclaims:
//   - "PENDING" (amber) vs "CONFIRMED" (green) exactly as the sidecar
//     reports — never a success affordance before success==true
//     (docs/03 §3.5 no silent success).
//   - Deletion shown as the sidecar's CLAIM label, which never says
//     "verified" (docs/04 §4.7).
//   - It holds NO keys; every step goes through the sidecar (OD-2).
using System;
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
        private readonly SidecarClient _sidecar;
        private readonly TextBlock _status = new TextBlock { FontSize = 16, TextWrapping = TextWrapping.Wrap };
        private readonly TextBlock _deletion = new TextBlock { TextWrapping = TextWrapping.Wrap, Foreground = Brushes.DimGray };
        private readonly TextBox _log = new TextBox
        {
            IsReadOnly = true, AcceptsReturn = true, TextWrapping = TextWrapping.Wrap,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Height = 200,
            FontFamily = new FontFamily("Consolas"), Background = Brushes.Black, Foreground = Brushes.LightGreen,
        };
        private readonly Button _bSetup = new Button { Content = "1 · Setup + Mint NFT", Margin = new Thickness(0, 0, 6, 0) };
        private readonly Button _bSwap = new Button { Content = "2 · Sign & broadcast swap", Margin = new Thickness(0, 0, 6, 0), IsEnabled = false };
        private readonly Button _bConfirm = new Button { Content = "3 · Confirm (mine block)", Margin = new Thickness(0, 0, 6, 0), IsEnabled = false };
        private readonly Button _bAttest = new Button { Content = "4 · Attest deletion", IsEnabled = false };

        public MainWindow()
        {
            Title = "nft-wallet-bsv — Stage 1 (BSV only; non-custodial; the renderer holds NO keys)";
            Width = 860;
            Height = 640;

            string baseUrl = Environment.GetEnvironmentVariable("NFTBSV_SIDECAR");
            if (string.IsNullOrEmpty(baseUrl)) baseUrl = "http://127.0.0.1:8090";
            _sidecar = new SidecarClient(baseUrl);

            var buttons = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 4, 0, 4) };
            buttons.Children.Add(_bSetup);
            buttons.Children.Add(_bSwap);
            buttons.Children.Add(_bConfirm);
            buttons.Children.Add(_bAttest);

            _bSetup.Click += async (s, e) => await RunAction(_bSetup, _bSwap, "/action/setup-mint");
            _bSwap.Click += async (s, e) => await RunAction(_bSwap, _bConfirm, "/action/swap");
            _bConfirm.Click += async (s, e) => await RunAction(_bConfirm, _bAttest, "/action/confirm");
            _bAttest.Click += async (s, e) => await RunAction(_bAttest, null, "/action/attest");

            var panel = new StackPanel { Margin = new Thickness(16) };
            panel.Children.Add(Bold("Drive a real regtest exchange (steps run on-chain):"));
            panel.Children.Add(buttons);
            panel.Children.Add(Bold("Exchange status"));
            panel.Children.Add(_status);
            panel.Children.Add(new Separator());
            panel.Children.Add(Bold("Live log (real txids)"));
            panel.Children.Add(_log);
            panel.Children.Add(new Separator());
            panel.Children.Add(Bold("Deletion"));
            panel.Children.Add(_deletion);
            Content = panel;

            var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            timer.Tick += async (s, e) => await RefreshAsync();
            timer.Start();
        }

        private static TextBlock Bold(string text)
        {
            return new TextBlock { Text = text, FontWeight = FontWeights.Bold, Margin = new Thickness(0, 8, 0, 2) };
        }

        private async Task RunAction(Button self, Button? next, string path)
        {
            self.IsEnabled = false;
            try
            {
                ActionResp? r = await _sidecar.PostActionAsync(path);
                if (r != null)
                {
                    _log.Text = string.Join("\n", r.log ?? Array.Empty<string>());
                    _log.ScrollToEnd();
                    if (r.ok)
                    {
                        if (next != null) next.IsEnabled = true;
                    }
                    else
                    {
                        self.IsEnabled = true;
                        MessageBox.Show(r.error ?? "action failed", "Step failed");
                    }
                }
            }
            catch (Exception ex)
            {
                self.IsEnabled = true;
                MessageBox.Show(ex.Message, "Error");
            }
        }

        private async Task RefreshAsync()
        {
            try
            {
                StatusDto? st = await _sidecar.GetStatusAsync();
                if (st == null) return;
                _status.Text = st.label;
                _status.Foreground = st.failed ? Brushes.Firebrick
                    : st.success ? Brushes.DarkGreen
                    : Brushes.DarkGoldenrod; // pending / in-progress
                _deletion.Text = st.deletion_label; // never claims "verified"
            }
            catch (Exception ex)
            {
                _status.Text = "sidecar unreachable: " + ex.Message;
                _status.Foreground = Brushes.Gray;
            }
        }
    }
}
