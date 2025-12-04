using System.Text;
using System.Text.Json;

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

        // simple in-memory cache for bearer token
        private string _cachedBearerToken;
        private DateTime _cachedBearerExpiresAt = DateTime.MinValue;

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

        // Obtain bearer token: call access token API if configured, otherwise fall back to static config
        private async Task<string> GetBearerTokenAsync()
        {
            var accessEndpoint = _config["UBI_AccessToken_API"];
            // fallback to static token if no endpoint configured
            if (string.IsNullOrWhiteSpace(accessEndpoint))
                return _config["UBI_BearerToken"];

            // return cached token if still valid
            if (!string.IsNullOrEmpty(_cachedBearerToken) && DateTime.UtcNow < _cachedBearerExpiresAt)
                return _cachedBearerToken;

            if (_http == null)
            {
                _logger?.LogError("HttpClient is null while attempting to fetch access token.");
                throw new InvalidOperationException("HttpClient not available for access token request.");
            }

            // Build plain token request body per bank docs
            var tokenRequest = new
            {
                userName = _config["UBI_AccessToken_UserName"] ?? _config["UBI_AccessToken_ClientId"],
                grantType = _config["UBI_AccessToken_GrantType"] ?? "password",
                clientId = _config["UBI_AccessToken_ClientId"],
                clientSecret = _config["UBI_AccessToken_ClientSecret"],
                password = _config["UBI_AccessToken_Password"],
                scope = _config["UBI_AccessToken_Scope"] ?? "offline_access"
            };

            string plainReqJson = JsonSerializer.Serialize(tokenRequest);

            // encrypt payload using bank class
            string encryptedReq = Encrypt(plainReqJson);

            var requestObject = new { reqData = encryptedReq };

            var msg = new HttpRequestMessage(HttpMethod.Post, accessEndpoint);
            var apiToken = _config["UBI_ApiToken"];
            if (!string.IsNullOrEmpty(apiToken))
                msg.Headers.Add("apiToken", apiToken);

            msg.Content = new StringContent(JsonSerializer.Serialize(requestObject), Encoding.UTF8, "application/json");

            var response = await _http.SendAsync(msg);
            var body = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _logger?.LogError("AccessToken API call failed: {Status} {Body}", response.StatusCode, body);
                throw new Exception($"AccessToken API returned HTTP {response.StatusCode}");
            }

            try
            {
                using var doc = JsonDocument.Parse(body);

                // bank returns { "respData": "<encrypted>" , "msgId": "" }
                if (!doc.RootElement.TryGetProperty("respData", out var respEncEl))
                {
                    _logger?.LogError("AccessToken API response missing respData. Body: {Body}", body);
                    throw new Exception("AccessToken API response missing respData");
                }

                string respEnc = respEncEl.GetString();
                if (string.IsNullOrEmpty(respEnc))
                {
                    _logger?.LogError("AccessToken API respData empty. Body: {Body}", body);
                    throw new Exception("AccessToken API respData empty");
                }

                // decrypt respData
                string decrypted = Decrypt(respEnc);

                using var respDoc = JsonDocument.Parse(decrypted);

                // common token field names
                string token = null;
                int expiresIn = 0;

                if (respDoc.RootElement.TryGetProperty("access_token", out var at) && at.ValueKind == JsonValueKind.String)
                    token = at.GetString();
                else if (respDoc.RootElement.TryGetProperty("accessToken", out var at2) && at2.ValueKind == JsonValueKind.String)
                    token = at2.GetString();
                else if (respDoc.RootElement.TryGetProperty("token", out var at3) && at3.ValueKind == JsonValueKind.String)
                    token = at3.GetString();

                if (respDoc.RootElement.TryGetProperty("expires_in", out var exEl))
                {
                    if (exEl.ValueKind == JsonValueKind.Number && exEl.TryGetInt32(out var v))
                        expiresIn = v;
                    else if (exEl.ValueKind == JsonValueKind.String && int.TryParse(exEl.GetString(), out var v2))
                        expiresIn = v2;
                }

                if (string.IsNullOrEmpty(token))
                {
                    _logger?.LogError("AccessToken API decrypted response did not contain access token. Decrypted: {Decrypted}", decrypted);
                    throw new Exception("AccessToken API response did not contain token");
                }

                _cachedBearerToken = token;

                // docs give expires_in (sample "900") — treat value as seconds if plausible; otherwise default 5 minutes
                if (expiresIn > 0)
                    _cachedBearerExpiresAt = DateTime.UtcNow.AddSeconds(expiresIn - 30);
                else
                    _cachedBearerExpiresAt = DateTime.UtcNow.AddMinutes(5);

                return _cachedBearerToken;
            }
            catch (JsonException je)
            {
                _logger?.LogError(je, "Failed to parse AccessToken API decrypted response. Body: {Body}", body);
                throw;
            }
        }

        // 🔥 MAIN API CALL
        public async Task<string> SendEncryptedRequestAsync(string plainJson)
        {
            string apiToken = _config["UBI_ApiToken"];
            string bearerToken = await GetBearerTokenAsync();
            string endpoint = _config["UBI_PaymentEndpoint"];

            // 🔥 Encrypt using bank class
            string encrypted = Encrypt(plainJson);

            // try to extract msgId from plainJson if present (bank examples include msgId as top-level)
            string msgId = string.Empty;
            try
            {
                using var doc = JsonDocument.Parse(plainJson);
                if (doc.RootElement.TryGetProperty("msgId", out var idEl) && idEl.ValueKind == JsonValueKind.String)
                    msgId = idEl.GetString() ?? string.Empty;
                else if (doc.RootElement.TryGetProperty("Message", out var m) && m.ValueKind == JsonValueKind.String)
                    msgId = m.GetString() ?? string.Empty;
            }
            catch (JsonException)
            {
                // plainJson might be arbitrary; ignore and send empty msgId
            }

            // Bank expects top-level { "reqData": "<encrypted>", "msgId": "..." }
            object requestObject = string.IsNullOrEmpty(msgId) ? new { reqData = encrypted } : new { reqData = encrypted, msgId = msgId };
            string reqJson = JsonSerializer.Serialize(requestObject);

            var msg = new HttpRequestMessage(HttpMethod.Post, endpoint);
            if (!string.IsNullOrEmpty(apiToken))
                msg.Headers.Add("apiToken", apiToken);
            if (!string.IsNullOrEmpty(bearerToken))
                msg.Headers.Add("Authorization", $"Bearer {bearerToken}");
            msg.Content = new StringContent(reqJson, Encoding.UTF8, "application/json");

            var response = await _http.SendAsync(msg);
            string body = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("UBI Error: {Status} {Body}", response.StatusCode, body);
                throw new Exception($"UBI returned HTTP {response.StatusCode}");
            }

            using var docResp = JsonDocument.Parse(body);

            if (!docResp.RootElement.TryGetProperty("respData", out var respEnc))
                return body;

            // decrypt bank response
            string decrypted = Decrypt(respEnc.GetString());
            return decrypted;
        }
    }
}





//using ePayment_API.DTOs;
//using Microsoft.Extensions.Configuration;
//using Microsoft.Extensions.Logging;
//using System;
//using System.Net.Http;
//using System.Text;
//using System.Text.Json;
//using System.Threading.Tasks;

//namespace ePayment_API.classes
//{
//    public class UBI
//    {
//        private readonly IConfiguration _config;
//        private readonly ILogger<UBI> _logger;
//        private readonly HttpClient _http;

//        // simple in-memory cache for bearer token
//        private string _cachedBearerToken;
//        private DateTime _cachedBearerExpiresAt = DateTime.MinValue;

//        public UBI(IConfiguration config, ILogger<UBI> logger, HttpClient http)
//        {
//            _config = config;
//            _logger = logger;
//            _http = http;
//        }

//        // 🔥 USE BANK PROVIDED ENCRYPT CLASS
//        private string Encrypt(string plainText)
//        {
//            string password = _config["UBI_EncryptionPassword"];
//            return AesGcmPayAPIUBI.Encrypt(plainText, password);
//        }

//        private string Decrypt(string encrypted)
//        {
//            string password = _config["UBI_EncryptionPassword"];
//            return AesGcmPayAPIUBI.Decrypt(encrypted, password);
//        }

//        // Obtain bearer token: prefer calling access token API if configured, otherwise fall back to static config
//        private async Task<string> GetBearerTokenAsync()
//        {
//            // if no access token endpoint configured, use static token from config
//            var accessEndpoint = _config["UBI_AccessToken_API"];
//            if (string.IsNullOrWhiteSpace(accessEndpoint))
//            {
//                return _config["UBI_BearerToken"];
//            }

//            // return cached token if still valid
//            if (!string.IsNullOrEmpty(_cachedBearerToken) && DateTime.UtcNow < _cachedBearerExpiresAt)
//                return _cachedBearerToken;

//            if (_http == null)
//            {
//                _logger?.LogError("HttpClient is null while attempting to fetch access token.");
//                throw new InvalidOperationException("HttpClient not available for access token request.");
//            }

//            var msg = new HttpRequestMessage(HttpMethod.Post, accessEndpoint);

//            // Add apiToken header if present (used by other calls)
//            var apiToken = _config["UBI_ApiToken"];
//            if (!string.IsNullOrEmpty(apiToken))
//                msg.Headers.Add("apiToken", apiToken);

//            // Optionally send client credentials if configured (UBI_AccessToken_ClientId / UBI_AccessToken_ClientSecret)
//            var clientId = _config["UBI_AccessToken_ClientId"];
//            var clientSecret = _config["UBI_AccessToken_ClientSecret"];

//            if (!string.IsNullOrEmpty(clientId) && !string.IsNullOrEmpty(clientSecret))
//            {
//                var payload = new { clientId = clientId, clientSecret = clientSecret };
//                msg.Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
//            }
//            else
//            {
//                // many banks accept an empty JSON body or some fixed body. Send empty JSON to be safe.
//                msg.Content = new StringContent("{}", Encoding.UTF8, "application/json");
//            }

//            var response = await _http.SendAsync(msg);
//            var body = await response.Content.ReadAsStringAsync();

//            if (!response.IsSuccessStatusCode)
//            {
//                _logger?.LogError("AccessToken API call failed: {Status} {Body}", response.StatusCode, body);
//                throw new Exception($"AccessToken API returned HTTP {response.StatusCode}");
//            }

//            try
//            {
//                using var doc = JsonDocument.Parse(body);

//                // Common token field names to try
//                string token = null;
//                int expiresIn = 0;

//                foreach (var name in new[] { "accessToken", "access_token", "token", "bearerToken", "bearer_token" })
//                {
//                    if (doc.RootElement.TryGetProperty(name, out var el) && el.ValueKind == JsonValueKind.String)
//                    {
//                        token = el.GetString();
//                        break;
//                    }
//                }

//                // sometimes token is wrapped inside data
//                if (token == null && doc.RootElement.TryGetProperty("data", out var dataEl) && dataEl.ValueKind == JsonValueKind.Object)
//                {
//                    foreach (var name in new[] { "accessToken", "access_token", "token", "bearerToken", "bearer_token" })
//                    {
//                        if (dataEl.TryGetProperty(name, out var el) && el.ValueKind == JsonValueKind.String)
//                        {
//                            token = el.GetString();
//                            break;
//                        }
//                    }

//                    if (dataEl.TryGetProperty("expires_in", out var expEl) && expEl.ValueKind == JsonValueKind.Number && expEl.TryGetInt32(out var v2))
//                        expiresIn = v2;
//                }

//                if (token == null)
//                {
//                    // also try root expires_in
//                    if (doc.RootElement.TryGetProperty("expires_in", out var expEl) && expEl.ValueKind == JsonValueKind.Number && expEl.TryGetInt32(out var v))
//                        expiresIn = v;
//                }

//                if (string.IsNullOrEmpty(token))
//                {
//                    _logger?.LogError("AccessToken API response did not contain a recognizable token. Body: {Body}", body);
//                    throw new Exception("AccessToken API response did not contain token");
//                }

//                _cachedBearerToken = token;
//                // set expiry: use expires_in if returned, otherwise default short cache
//                if (expiresIn > 0)
//                    _cachedBearerExpiresAt = DateTime.UtcNow.AddSeconds(expiresIn - 30); // small buffer
//                else
//                    _cachedBearerExpiresAt = DateTime.UtcNow.AddMinutes(5);

//                return _cachedBearerToken;
//            }
//            catch (JsonException je)
//            {
//                _logger?.LogError(je, "Failed to parse AccessToken API response: {Body}", body);
//                throw;
//            }
//        }

//        // 🔥 MAIN API CALL
//        public async Task<string> SendEncryptedRequestAsync(string plainJson)
//        {
//            string apiToken = _config["UBI_ApiToken"];
//            // now dynamically obtain bearer token (cached)
//            string bearerToken = await GetBearerTokenAsync();
//            string endpoint = _config["UBI_PaymentEndpoint"];

//            // 🔥 Encrypt using bank class
//            string encrypted = Encrypt(plainJson);

//            // 🔥 Bank requires:
//            // {
//            //     "reqData": "<encrypted_string>"
//            // }
//            var requestObject = new { reqData = encrypted };
//            string reqJson = JsonSerializer.Serialize(requestObject);

//            var msg = new HttpRequestMessage(HttpMethod.Post, endpoint);
//            if (!string.IsNullOrEmpty(apiToken))
//                msg.Headers.Add("apiToken", apiToken);
//            if (!string.IsNullOrEmpty(bearerToken))
//                msg.Headers.Add("Authorization", $"Bearer {bearerToken}");
//            msg.Content = new StringContent(reqJson, Encoding.UTF8, "application/json");

//            var response = await _http.SendAsync(msg);
//            string body = await response.Content.ReadAsStringAsync();

//            if (!response.IsSuccessStatusCode)
//            {
//                _logger.LogError("UBI Error: {Status} {Body}", response.StatusCode, body);
//                throw new Exception($"UBI returned HTTP {response.StatusCode}");
//            }

//            using var doc = JsonDocument.Parse(body);

//            if (!doc.RootElement.TryGetProperty("respData", out var respEnc))
//                return body;

//            // 🔥 Decrypt using bank class
//            return Decrypt(respEnc.GetString());
//        }
//    }
//}
