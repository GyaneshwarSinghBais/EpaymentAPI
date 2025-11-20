using ePayment_API.DTOs;
using Microsoft.SqlServer.Server;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Web;

namespace ePayment_API.classes
{
    public class UBI1
    {
        private readonly IConfiguration _config;
        private readonly ILogger<UBI> _logger;
        private readonly HttpClient _http;

        // Parameters from UBI PDF
        private const int IvLength = 16;
        private const int SaltLength = 16;
        private const int TagLength = 16;
        private const int KeyLength = 32;
        private const int Iterations = 65536;

        public UBI1(IConfiguration config, ILogger<UBI> logger, HttpClient http)
        {
            _config = config;
            _logger = logger;
            _http = http;
        }

        // Encrypt plaintext JSON → Base64(IV | Cipher | Tag | Salt)
        public string EncryptString(string plaintext, string password)
        {
            byte[] plainBytes = Encoding.UTF8.GetBytes(plaintext);
            byte[] iv = RandomNumberGenerator.GetBytes(IvLength);
            byte[] salt = RandomNumberGenerator.GetBytes(SaltLength);

            using var derive = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithmName.SHA256);
            byte[] key = derive.GetBytes(KeyLength);

            byte[] cipher = new byte[plainBytes.Length];
            byte[] tag = new byte[TagLength];

            using var aes = new AesGcm(key);
            aes.Encrypt(iv, plainBytes, cipher, tag);

            byte[] output = new byte[iv.Length + cipher.Length + tag.Length + salt.Length];
            Buffer.BlockCopy(iv, 0, output, 0, IvLength);
            Buffer.BlockCopy(cipher, 0, output, IvLength, cipher.Length);
            Buffer.BlockCopy(tag, 0, output, IvLength + cipher.Length, TagLength);
            Buffer.BlockCopy(salt, 0, output, IvLength + cipher.Length + TagLength, SaltLength);

            return Convert.ToBase64String(output);
        }

        // Decrypt Base64(IV | Cipher | Tag | Salt)
        public string DecryptString(string encryptedBase64, string password)
        {
            byte[] all = Convert.FromBase64String(encryptedBase64);

            byte[] iv = new byte[IvLength];
            byte[] salt = new byte[SaltLength];
            byte[] tag = new byte[TagLength];

            int cipherLen = all.Length - IvLength - SaltLength - TagLength;
            byte[] cipher = new byte[cipherLen];

            Buffer.BlockCopy(all, 0, iv, 0, IvLength);
            Buffer.BlockCopy(all, IvLength, cipher, 0, cipherLen);
            Buffer.BlockCopy(all, IvLength + cipherLen, tag, 0, TagLength);
            Buffer.BlockCopy(all, IvLength + cipherLen + TagLength, salt, 0, SaltLength);

            using var derive = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithmName.SHA256);
            byte[] key = derive.GetBytes(KeyLength);

            byte[] plain = new byte[cipherLen];

            using var aes = new AesGcm(key);
            aes.Decrypt(iv, cipher, tag, plain);

            return Encoding.UTF8.GetString(plain);
        }

        // Call UBI API and return DECRYPTED response
        public async Task<string> SendEncryptedRequestAsync(string plainJson)
        {
            string apiToken = _config["UBI_ApiToken"];
            string bearerToken = _config["UBI_BearerToken"];
            string password = _config["UBI_EncryptionPassword"];
            string endpoint = _config["UBI_PaymentEndpoint"];

            string encrypted = EncryptString(plainJson, password);

            var req = new { reqData = encrypted };
            string reqJson = System.Text.Json.JsonSerializer.Serialize(req);


            var msg = new HttpRequestMessage(HttpMethod.Post, endpoint);
            msg.Headers.Add("apiToken", apiToken);
            msg.Headers.Add("Authorization", $"Bearer {bearerToken}");
            msg.Content = new StringContent(reqJson, Encoding.UTF8, "application/json");

            var response = await _http.SendAsync(msg);
            string body = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("UBI Error: {Status} {Body}", response.StatusCode, body);
                throw new Exception($"UBI returned HTTP {response.StatusCode}");
            }

            using var doc = JsonDocument.Parse(body);

            if (!doc.RootElement.TryGetProperty("respData", out var respEnc))
                return body;

            return DecryptString(respEnc.GetString(), password);
        }
    }
}
