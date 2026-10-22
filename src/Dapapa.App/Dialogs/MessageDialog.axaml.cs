using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Dapapa.Core;

namespace Dapapa.App.Dialogs
{
    public enum MessageDialogButtons { Ok, YesNo }

    /// <summary>Replacement for the Windows message box in the app's own style.</summary>
    public partial class MessageDialog : Window
    {
        public MessageDialog() : this("", "", MessageDialogButtons.Ok) { }

        public MessageDialog(string message, string title, MessageDialogButtons buttons)
        {
            InitializeComponent();
            Title = HeadingText.Text = title;
            MessageText.Text = message;
            bool question = buttons == MessageDialogButtons.YesNo;
            PrimaryButton.Content = Localization.T(question ? "Yes" : "OK");
            SecondaryButton.Content = Localization.T("No");
            SecondaryButton.IsVisible = question;
            KeyDown += (_, e) =>
            {
                if (e.Key == Key.Escape) Close(false);
                else if (e.Key == Key.Enter) Close(true);
            };
            Opened += (_, _) => PrimaryButton.Focus();
        }

        /// <summary>Shows the dialog over <paramref name="owner"/>; true means OK or Yes.</summary>
        public static Task<bool> ShowAsync(Window owner, string message, string title, MessageDialogButtons buttons = MessageDialogButtons.Ok) =>
            ShowHandler(owner, message, title, buttons);

        /// <summary>Replaceable so UI tests can answer dialogs without a modal loop.</summary>
        internal static Func<Window, string, string, MessageDialogButtons, Task<bool>> ShowHandler { get; set; } =
            (owner, message, title, buttons) => new MessageDialog(message, title, buttons).ShowDialog<bool>(owner);

        private void PrimaryButton_Click(object? sender, RoutedEventArgs e) => Close(true);

        private void SecondaryButton_Click(object? sender, RoutedEventArgs e) => Close(false);

        private void Root_PointerPressed(object? sender, PointerPressedEventArgs e)
        {
            if (e.GetCurrentPoint(this).Properties.IsLeftButtonPressed) BeginMoveDrag(e);
        }
    }
}
