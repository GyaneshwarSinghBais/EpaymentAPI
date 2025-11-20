using ePayment_API.Data;
using Microsoft.AspNetCore.Http;


using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

using System.Security.Cryptography;
using System.Net;
using System;
using ePayment_API.DTOs;

using System.Text;

using Newtonsoft.Json;
using System.Security.Cryptography.X509Certificates;

namespace ePayment_API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class EpayController : ControllerBase
    {
        private readonly DbContextHIMIS _context;
        private readonly ILogger<EpayController> _logger;
        public EpayController(DbContextHIMIS context, ILogger<EpayController> logger)
        {
            _context = context;
            _logger = logger;
        }

        [HttpGet("GetDistrict")]
        public async Task<ActionResult<IEnumerable<GetDistrictDTO>>> GetDistrict()
        {
            string query = $@" select District_ID, DBStart_Name_En from Districts ";
            var result = await _context.GetDistrictDbSet
                .FromSqlRaw(query)
                .ToListAsync();

            return Ok(result);
        }

        [HttpPost("sendPayment")]
        public async Task<IActionResult> SendPayment()
        {
            // 1. Hardcoded test data

            //var payload = new
            //{
            //    tranRefNo = "202401081032010",
            //    amount = "1.00",
            //    senderAcctNo = "000405002777",
            //    beneAccNo = "000405001611",
            //    beneName = "PratikMundhe",
            //    beneIFSC = "SBIN0003060",
            //    narration1 = "NEFT transaction",
            //    narration2 = "PritamGadekar",
            //    crpId = "SESPRODUCT",
            //    crpUsr = "389018",
            //    aggrId = "MESCOMP0302",
            //    aggrName = "CGMSC",
            //    urn = "CGMSC123",
            //    txnType = "RGS",
            //    WORKFLOW_REQD = "N"
            //};

            var payload = new
            {
                tranRefNo = "202401081032010",
                amount = "1.00",
                senderAcctNo = "000405002500",
                beneAccNo = "000451000301",
                beneName = "PratikMundhe",
                beneIFSC = "SBIN0003060",
                narration1 = "NEFT transaction",
                narration2 = "PritamGadekar",
                crpId = "SESPRODUCT",
                crpUsr = "BAN339226",
                aggrId = "MESCOMP0302",
                aggrName = "CGMSC",
                urn = "CGMSC123",
                txnType = "RGS",
                WORKFLOW_REQD = "N",
                BENLEI = ""
            };

            // 2. Generate RANDOMNO1 (AES key)
            string randomKey = GenerateRandomNumber(16);

            // 3. Encrypt RANDOMNO1 using ICICI public key (RSA)
            string encrKey = EncryptRsaBase64(randomKey, @"g:\gyan\ePayment_API\ePayment_API\Keys\icici_public.cer");

            // 4. Generate RANDOMNO2 (IV)
            string randomIV = GenerateRandomNumber(16);

            // 5. Concatenate RANDOMNO2 and JSON data
            string jsonPayload = JsonConvert.SerializeObject(payload);
            string dataToEncrypt = randomIV + jsonPayload;

            // 6. AES CBC Encryption (PKCS5)
            string encrData = EncryptAesCbcBase64(dataToEncrypt, randomKey, randomIV);

            // 7. Send to ICICI API
            return await PostToIciciAsync(encrKey, encrData);
        }

        private static string GenerateRandomNumber(int length)
        {
            var random = new Random();
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string(Enumerable.Repeat(chars, length)
              .Select(s => s[random.Next(s.Length)]).ToArray());
        }

        //private static string EncryptRsaBase64(string plainText, string publicKeyPath)
        //{
        //    byte[] dataToEncrypt = Encoding.UTF8.GetBytes(plainText);
        //    using var rsa = new RSACryptoServiceProvider();

        //    // Load public key
        //    var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(publicKeyPath);
        //    rsa.ImportParameters(((RSACryptoServiceProvider)cert.PublicKey.Key).ExportParameters(false));

        //    byte[] encrypted = rsa.Encrypt(dataToEncrypt, false); // PKCS1
        //    return Convert.ToBase64String(encrypted);
        //}

        private static string EncryptRsaBase64(string plainText, string publicKeyPath)
        {
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes(plainText);

            // Load public key
            var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(publicKeyPath);
            using RSA rsa = cert.GetRSAPublicKey(); // Correct and safe method

            byte[] encrypted = rsa.Encrypt(dataToEncrypt, RSAEncryptionPadding.Pkcs1);
            return Convert.ToBase64String(encrypted);
        }

        private static string EncryptAesCbcBase64(string plainText, string key, string iv)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] ivBytes = Encoding.UTF8.GetBytes(iv);
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);

            using var aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = keyBytes;
            aes.IV = ivBytes;

            using var encryptor = aes.CreateEncryptor();
            byte[] cipherBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);

            return Convert.ToBase64String(cipherBytes);
        }


        private async Task<IActionResult> PostToIciciAsync(string encryptedKey, string encryptedData)
        {
            using var httpClient = new HttpClient();

            var payload = new
            {
                encryptedKey = encryptedKey,
                encryptedData = encryptedData
            };

            var json = JsonConvert.SerializeObject(payload);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await httpClient.PostAsync("https://apibankingonesandbox.icicibank.com/api/v1/composite-payment", content);
            var responseContent = await response.Content.ReadAsStringAsync();

            return Ok(new
            {
                StatusCode = response.StatusCode,
                Response = responseContent
            });
        }


        //private async Task<IActionResult> PostToIciciAsync(string encryptedKey, string encryptedData)
        //{
        //    var httpClient = new HttpClient();

        //    // Set base address and headers
        //    httpClient.BaseAddress = new Uri("https://apibankingonesandbox.icicibank.com");
        //    httpClient.DefaultRequestHeaders.Add("client_id", "YOUR_CLIENT_ID");
        //    httpClient.DefaultRequestHeaders.Add("client_secret", "YOUR_CLIENT_SECRET");

        //    var payload = new
        //    {
        //        encryptedKey = encryptedKey,
        //        encryptedData = encryptedData
        //    };

        //    var json = JsonConvert.SerializeObject(payload);
        //    var content = new StringContent(json, Encoding.UTF8, "application/json");

        //    var response = await httpClient.PostAsync("/api/v1/composite-payment", content);
        //    var responseContent = await response.Content.ReadAsStringAsync();

        //    return Ok(new
        //    {
        //        StatusCode = response.StatusCode,
        //        Response = responseContent
        //    });
        //}
    }
}
