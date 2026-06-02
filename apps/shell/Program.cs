// WS7 shell entry point. A code-only WPF app (no XAML) whose whole job is
// to render the sidecar's HONEST state and never overclaim:
//   - It shows "PENDING" vs "CONFIRMED" exactly as the sidecar reports
//     (never a success affordance before the sidecar's success==true,
//     docs/03 §3.5 no silent success).
//   - It shows the deletion status as the sidecar's CLAIM label, which
//     never says "verified" (docs/04 §4.7).
//   - It holds NO keys; everything goes through the sidecar (OD-2).
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
        private readonly TextBlock _terms = new TextBlock { TextWrapping = TextWrapping.Wrap, FontFamily = new FontFamily("Consolas") };
        private readonly Button _confirm = new Button { Content = "Sign & Confirm swap", IsEnabled = false, Margin = new Thickness(0, 6, 0, 0) };

        public MainWindow()
        {
            Title = "nft-wallet-bsv — Stage 1 (BSV only; non-custodial; the renderer holds NO keys)";
            Width = 760;
            Height = 540;

            string baseUrl = Environment.GetEnvironmentVariable("NFTBSV_SIDECAR");
            if (string.IsNullOrEmpty(baseUrl)) baseUrl = "http://127.0.0.1:8090";
            _sidecar = new SidecarClient(baseUrl);

            var panel = new StackPanel { Margin = new Thickness(16) };
            panel.Children.Add(Bold("Exchange status"));
            panel.Children.Add(_status);
            panel.Children.Add(new Separator());
            panel.Children.Add(Bold("Swap review — the EXACT terms you are signing (shown before any signature)"));
            panel.Children.Add(_terms);
            panel.Children.Add(_confirm);
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

        private async Task RefreshAsync()
        {
            try
            {
                StatusDto? st = await _sidecar.GetStatusAsync();
                if (st == null) return;
                // HONEST rendering: success ONLY when the sidecar says so.
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
