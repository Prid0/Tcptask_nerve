using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

class ClientApp
{
    static string serverIp = "127.0.0.1";
    static int serverPort = 9000;
    static string encryptionKey = "MySuperSecretPassphrase!ChangeMe";

    static async Task Main(string[] args)
    {
        if (args.Length >= 1) serverIp = args[0];
        if (args.Length >= 2 && int.TryParse(args[1], out int parsedPort)) serverPort = parsedPort;
        if (args.Length >= 3) encryptionKey = args[2];

        Console.WriteLine($"[Client] Connecting to {serverIp}:{serverPort}...");
        using var client = new TcpClient();
        await client.ConnectAsync(serverIp, serverPort);
        Console.WriteLine("[Client] Connected!");

        using var networkStream = client.GetStream();
        using var reader = new StreamReader(networkStream, Encoding.UTF8, leaveOpen: true);
        using var writer = new StreamWriter(networkStream, Encoding.UTF8, leaveOpen: true) { AutoFlush = true };

        Console.WriteLine("\nEnter command in the format SetX-KeyName (e.g., SetA-Two):");
        string userCommand = Console.ReadLine()?.Trim() ?? "";

        if (string.IsNullOrWhiteSpace(userCommand))
        {
            Console.WriteLine("[Client] Empty command. Exiting.");
            return;
        }

        string encryptedCommand = AesEncryptionHelper.EncryptStringToBase64(userCommand, encryptionKey);
        await writer.WriteLineAsync(encryptedCommand);
        Console.WriteLine("[Client] Command encrypted and sent to server.");

        Console.WriteLine("[Client] Waiting for server response...\n");
        while (true)
        {
            string? encryptedResponse = await reader.ReadLineAsync();
            if (string.IsNullOrWhiteSpace(encryptedResponse))
            {
                Console.WriteLine("[Client] Empty or null response. Ending connection.");
                break;
            }

            string decryptedResponse;
            try
            {
                decryptedResponse = AesEncryptionHelper.DecryptBase64ToString(encryptedResponse, encryptionKey);
            }
            catch
            {
                decryptedResponse = "(decryption error)";
            }

            if (decryptedResponse == "END")
            {
                Console.WriteLine("[Client] Server finished sending data. Closing connection.");
                break;
            }

            if (decryptedResponse == "EMPTY")
            {
                Console.WriteLine("[Client] Server returned EMPTY (invalid or unknown command).");
                break;
            }

            Console.WriteLine($"[Client] Received: {decryptedResponse}");
        }

        Console.WriteLine("\n[Client] Connection closed.");
    }
}

// AES Encryption and Decryption Helper
static class AesEncryptionHelper
{
    static void GenerateKeyAndIV(string passphrase, out byte[] key, out byte[] iv)
    {
        byte[] salt = Encoding.UTF8.GetBytes("FixedSaltForDemo123"); // Must match server salt
        using var keyDeriver = new Rfc2898DeriveBytes(passphrase, salt, 100_000);
        key = keyDeriver.GetBytes(32);
        iv = keyDeriver.GetBytes(16);
    }

    public static string EncryptStringToBase64(string plainText, string passphrase)
    {
        GenerateKeyAndIV(passphrase, out byte[] key, out byte[] iv);
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using var ms = new MemoryStream();
        using (var cryptoStream = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
        using (var writer = new StreamWriter(cryptoStream, Encoding.UTF8))
        {
            writer.Write(plainText);
        }

        return Convert.ToBase64String(ms.ToArray());
    }

    public static string DecryptBase64ToString(string base64Cipher, string passphrase)
    {
        GenerateKeyAndIV(passphrase, out byte[] key, out byte[] iv);
        byte[] cipherBytes = Convert.FromBase64String(base64Cipher);
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using var ms = new MemoryStream(cipherBytes);
        using var cryptoStream = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read);
        using var reader = new StreamReader(cryptoStream, Encoding.UTF8);
        return reader.ReadToEnd();
    }
}
