using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

//using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Net.Http;


namespace ePayment_API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class GyanController : ControllerBase
    {

        [HttpPost("make-payment")]
        public async Task<IActionResult> MakePayment()
        {
            var payloadData = new Dictionary<string, object>
            {
                { "tranRefNo", "20250612104956" },
                { "bcID", "IBCKer00055" },
                { "crpId", "SESPRODUCT" },
                { "crpUsr", "BAN339226" },
                { "aggrId", "MESCOMP0302" },
                { "urn", "3kCy4sPuSqDNi4kggXJIoE568223" }
            };

            string payloadJson = JsonConvert.SerializeObject(payloadData);

            string encryptedRequest = EncryptRequest(payloadJson, out byte[] randomKey);

            string url = "https://apibankingonesandbox.icicibank.com/api/v1/composite-payment";
            using var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Add("apikey", "tqwr5u6KBKlFPydVYIe4AGSD0uHdnFES");
            httpClient.DefaultRequestHeaders.Add("x-priority", "0100");

            var response = await httpClient.PostAsync(url, new StringContent(encryptedRequest, Encoding.UTF8, "application/json"));
            string responseContent = await response.Content.ReadAsStringAsync();

            // Log for debugging
            Console.WriteLine("Request: " + encryptedRequest);
            Console.WriteLine("Response: " + responseContent);

            if (response.StatusCode == HttpStatusCode.Unauthorized)
                return Unauthorized(new { message = "Unauthorized. Check API key, IP whitelisting, and headers.", raw = responseContent });

            var parsed = JsonConvert.DeserializeObject<dynamic>(responseContent);
            string encryptedKey = parsed.encryptedKey;
            string encryptedData = parsed.encryptedData;

            if (string.IsNullOrEmpty(encryptedKey) || string.IsNullOrEmpty(encryptedData))
                return BadRequest(new { message = "Bank response does not contain encryptedKey or encryptedData", raw = responseContent });

            string decryptedKey = DecryptKey(Convert.FromBase64String(encryptedKey));
            string decryptedData = DecryptData(encryptedData, decryptedKey);

            return Ok(JsonConvert.DeserializeObject(decryptedData));
        }

        // Encrypts the payload
        private string EncryptRequest(string jsonData, out byte[] randomKey)
        {
            randomKey = GenerateRandomBytes(16);
            byte[] iv = GenerateRandomBytes(16);
            string randomIVStr = Encoding.UTF8.GetString(iv);
            string dataToEncrypt = randomIVStr + jsonData;

            string encryptedKey = EncryptRandomKey(randomKey);
            byte[] encryptedBytes = EncryptAES(dataToEncrypt, randomKey, iv);
            string encryptedData = Convert.ToBase64String(encryptedBytes);

            var final = new Dictionary<string, object>
            {
                { "requestId", Guid.NewGuid().ToString() },
                { "encryptedKey", encryptedKey },
                { "iv", Convert.ToBase64String(iv) },
                { "encryptedData", encryptedData },
                { "oaepHashingAlgorithm", "none" },
                { "service", "" },
                { "clientInfo", "" },
                { "optionalParam", "" }
            };

            return JsonConvert.SerializeObject(final);
        }

        private string EncryptRandomKey(byte[] randomKey)
        {
           
            var publicKeyCert = new X509Certificate2("g:\\gyan\\ePayment_API\\ePayment_API\\Keys\\icici_public.cer");
            using var rsa = publicKeyCert.GetRSAPublicKey();
            byte[] encryptedKey = rsa.Encrypt(randomKey, RSAEncryptionPadding.Pkcs1);
            return Convert.ToBase64String(encryptedKey);
        }

        
        private string DecryptKey(byte[] encryptedKey)
        {
            var cert = new X509Certificate2("C:\\inetpub\\wwwroot\\takneekiPub.pfx", "admin@1234", X509KeyStorageFlags.MachineKeySet);
            using var rsa = cert.GetRSAPrivateKey();
            byte[] decrypted = rsa.Decrypt(encryptedKey, RSAEncryptionPadding.Pkcs1);
            return Convert.ToBase64String(decrypted);
        }

        private string DecryptData(string encryptedDataBase64, string base64Key)
        {
            byte[] fullCipher = Convert.FromBase64String(encryptedDataBase64);
            byte[] key = Convert.FromBase64String(base64Key);

            byte[] iv = new byte[16];
            Array.Copy(fullCipher, 0, iv, 0, 16);

            byte[] cipherText = new byte[fullCipher.Length - 16];
            Array.Copy(fullCipher, 16, cipherText, 0, cipherText.Length);

            using var aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using var decryptor = aes.CreateDecryptor();
            using var ms = new MemoryStream(cipherText);
            using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
            using var sr = new StreamReader(cs);
            string result = sr.ReadToEnd();

            // Remove initial 16 characters (IV in plain text)
            return result.Substring(16);
        }

        private byte[] EncryptAES(string plainText, byte[] key, byte[] iv)
        {
            using var aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using var encryptor = aes.CreateEncryptor();
            using var ms = new MemoryStream();
            using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
            using (var sw = new StreamWriter(cs))
            {
                sw.Write(plainText);
            }

            return ms.ToArray();
        }

        private byte[] GenerateRandomBytes(int length)
        {
            byte[] bytes = new byte[length];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(bytes);
            return bytes;
        }

    }

    public class PaymentStatusRequest
    {
        public string tranRefNo { get; set; }
        public string bcID { get; set; }
        public string crpId { get; set; }
        public string crpUsr { get; set; }
        public string aggrId { get; set; }
        public string urn { get; set; }
    }
}
