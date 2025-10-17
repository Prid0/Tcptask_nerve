using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

class ServerApp
{
    static string serverIp = "127.0.0.1";
    static int serverPort = 9000;
    static string encryptionKey = "MySuperSecretPassphrase!ChangeMe";

    static Dictionary<string, Dictionary<string, int>> dataSets = new()
    {
        ["SetA"] = new() { ["One"] = 1, ["Two"] = 2 },
        ["SetB"] = new() { ["Three"] = 3, ["Four"] = 4 },
        ["SetC"] = new() { ["Five"] = 5, ["Six"] = 6 },
        ["SetD"] = new() { ["Seven"] = 7, ["Eight"] = 8 },
        ["SetE"] = new() { ["Nine"] = 9, ["Ten"] = 10 }
    };

    static async Task Main(string[] args)
    {
        if (args.Length >= 1) serverIp = args[0];
        if (args.Length >= 2 && int.TryParse(args[1], out int parsedPort)) serverPort = parsedPort;
        if (args.Length >= 3) encryptionKey = args[2];

        var endPoint = new IPEndPoint(IPAddress.Parse(serverIp), serverPort);
        var tcpListener = new TcpListener(endPoint);
        tcpListener.Start();

        Console.WriteLine($"[Server] Listening on {serverIp}:{serverPort}");
        Console.WriteLine("[Server] Waiting for clients...");

        while (true)
        {
            var client = await tcpListener.AcceptTcpClientAsync();
            Console.WriteLine("[Server] Connected: " + client.Client.RemoteEndPoint);
            _ = Task.Run(() => ProcessClientAsync(client));
        }
    }

    static async Task ProcessClientAsync(TcpClient client)
    {
        try
        {
            using (client)
            {
                using var networkStream = client.GetStream();
                using var reader = new StreamReader(networkStream, Encoding.UTF8, leaveOpen: true);
                using var writer = new StreamWriter(networkStream, Encoding.UTF8, leaveOpen: true) { AutoFlush = true };

                string encryptedMessage = await reader.ReadLineAsync();
                if (string.IsNullOrWhiteSpace(encryptedMessage))
                {
                    Console.WriteLine("[Server] Empty input received.");
                    return;
                }

                string decryptedCommand;
                try
                {
                    decryptedCommand = AesEncryptionHelper.DecryptBase64ToString(encryptedMessage, encryptionKey);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[Server] Failed to decrypt: " + ex.Message);
                    string emptyResponse = AesEncryptionHelper.EncryptStringToBase64("EMPTY", encryptionKey);
                    await writer.WriteLineAsync(emptyResponse);
                    return;
                }

                Console.WriteLine($"[Server] Command received: {decryptedCommand}");

                // Command format: "SetA-Two"
                var commandParts = decryptedCommand.Split('-', 2, StringSplitOptions.TrimEntries);
                if (commandParts.Length != 2)
                {
                    Console.WriteLine("[Server] Invalid command format.");
                    string emptyResponse = AesEncryptionHelper.EncryptStringToBase64("EMPTY", encryptionKey);
                    await writer.WriteLineAsync(emptyResponse);
                    return;
                }

                string setName = commandParts[0];
                string keyName = commandParts[1];

                if (!dataSets.TryGetValue(setName, out var selectedSet))
                {
                    Console.WriteLine($"[Server] Unknown set: '{setName}'.");
                    string emptyResponse = AesEncryptionHelper.EncryptStringToBase64("EMPTY", encryptionKey);
                    await writer.WriteLineAsync(emptyResponse);
                    return;
                }

                if (!selectedSet.TryGetValue(keyName, out int count))
                {
                    Console.WriteLine($"[Server] Key '{keyName}' not found in set '{setName}'.");
                    string emptyResponse = AesEncryptionHelper.EncryptStringToBase64("EMPTY", encryptionKey);
                    await writer.WriteLineAsync(emptyResponse);
                    return;
                }

                Console.WriteLine($"[Server] Sending {count} timestamp(s) to client {client.Client.RemoteEndPoint}.");

                for (int i = 0; i < count; i++)
                {
                    string timestamp = DateTime.Now.ToString("dd-MM-yyyy HH:mm:ss");
                    string encryptedTimestamp = AesEncryptionHelper.EncryptStringToBase64(timestamp, encryptionKey);
                    await writer.WriteLineAsync(encryptedTimestamp);
                    Console.WriteLine($"[Server] Sent ({i + 1}/{count}): {timestamp}");
                    await Task.Delay(1000);
                }

                string endMessage = AesEncryptionHelper.EncryptStringToBase64("END", encryptionKey);
                await writer.WriteLineAsync(endMessage);
                Console.WriteLine("[Server] Finished sending timestamps.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("[Server] Error while handling client: " + ex);
        }
    }
}

static class AesEncryptionHelper
{
    static void CreateKeyAndIV(string passphrase, out byte[] key, out byte[] iv)
    {
        byte[] salt = Encoding.UTF8.GetBytes("FixedSaltForDemo123");
        using var keyDeriver = new Rfc2898DeriveBytes(passphrase, salt, 100_000);
        key = keyDeriver.GetBytes(32);
        iv = keyDeriver.GetBytes(16);
    }

    public static string EncryptStringToBase64(string plainText, string passphrase)
    {
        CreateKeyAndIV(passphrase, out byte[] key, out byte[] iv);
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

    public static string DecryptBase64ToString(string encryptedBase64, string passphrase)
    {
        CreateKeyAndIV(passphrase, out byte[] key, out byte[] iv);
        byte[] encryptedBytes = Convert.FromBase64String(encryptedBase64);

        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using var ms = new MemoryStream(encryptedBytes);
        using var cryptoStream = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read);
        using var reader = new StreamReader(cryptoStream, Encoding.UTF8);
        return reader.ReadToEnd();
    }
}
