using ePayment_API.DTOs;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace ePayment_API.classes
{
    public class UBI
    {
        private readonly IConfiguration _config;
        private readonly ILogger<UBI> _logger;
        private readonly HttpClient _http;

        public UBI(IConfiguration config, ILogger<UBI> logger, HttpClient http)
        {
            _config = config;
            _logger = logger;
            _http = http;
        }

        // 🔥 USE BANK PROVIDED ENCRYPT CLASS
        private string Encrypt(string plainText)
        {
            string password = _config["UBI_EncryptionPassword"];
            return AesGcmPayAPIUBI.Encrypt(plainText, password);
        }

        private string Decrypt(string encrypted)
        {
            string password = _config["UBI_EncryptionPassword"];
            return AesGcmPayAPIUBI.Decrypt(encrypted, password);
        }

        // 🔥 MAIN API CALL
        public async Task<string> SendEncryptedRequestAsync(string plainJson)
        {
            string apiToken = _config["UBI_ApiToken"];
            string bearerToken = _config["UBI_BearerToken"];
            string endpoint = _config["UBI_PaymentEndpoint"];

            // 🔥 Encrypt using bank class
            string encrypted = Encrypt(plainJson);

            // 🔥 Bank requires:
            // {
            //     "reqData": "<encrypted_string>"
            // }
            var requestObject = new { reqData = encrypted };
            string reqJson = JsonSerializer.Serialize(requestObject);

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

            // 🔥 Decrypt using bank class
            return Decrypt(respEnc.GetString());
        }
    }
}
