using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using Laveyana.Security.Primitives;

namespace Laveyana.Security.App.LibraryWorkbench.Views;

public partial class LocalCryptographyView : UserControl
{
    public event Action<string>? ScenarioCompleted;

    public LocalCryptographyView()
    {
        InitializeComponent();
    }

    private void HashClick(object sender, RoutedEventArgs e)
    {
        byte[] data = Encoding.UTF8.GetBytes(InputText.Text);
        try
        {
            byte[] result = LocalCryptography.Sha256(data);
            try
            {
                HashOutput.Text = Convert.ToHexString(result);
                ScenarioCompleted?.Invoke("LocalCryptography.Sha256 completed on demonstration input.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(result);
            }
        }
        catch (Exception error)
        {
            HashOutput.Text = error.GetType().Name + ": " + error.Message;
            ScenarioCompleted?.Invoke("SHA-256 example failed (see application view).");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(data);
        }
    }

    private void HmacClick(object sender, RoutedEventArgs e)
    {
        byte[] key = LocalCryptography.GenerateRandomBytes(32);
        byte[] message = Encoding.UTF8.GetBytes("Laveyana Workbench: synthetic HMAC demo");
        byte[]? tag = null;
        try
        {
            tag = LocalCryptography.HmacSha256(key, message);
            bool correct = LocalCryptography.VerifyHmacSha256(key, message, tag);
            HmacOutput.Text = correct ? "Success: verification of a synthetic tag returned true."
                : "Verification unexpectedly failed.";
            ScenarioCompleted?.Invoke("HMAC demonstration completed; synthetic key disposed.");
        }
        catch (Exception error)
        {
            HmacOutput.Text = error.GetType().Name + ": " + error.Message;
            ScenarioCompleted?.Invoke("HMAC example failed (see application view).");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(message);
            if (tag is not null)
            {
                CryptographicOperations.ZeroMemory(tag);
            }
        }
    }
}
