using ePayment_API.Data;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;

namespace ePayment_API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class EpaymentController : ControllerBase
    {
        private readonly DbContextHIMIS _context;
        public EpaymentController(DbContextHIMIS context)
        {
            _context = context;
        }

        [HttpPost("send")]
        public IActionResult SendPayment()
        {
            string RANDOMNO1 = GenerateRandomDigits(16);
            string RANDOMNO2 = GenerateRandomDigits(16);

            // ICICI Public Key XML - your RSA modulus

            //string rsaModulus = @"rIGY8JhKHBsvvydhqLIGqiKOILsSHwyp";

            string rsaModulus = @"MIIE7jCCAtagAwIBAgIIWmFBujLqylAwDQYJKoZIhvcNAQEMBQAwFTETMBEGA1UEAwwKcnNhX2Fw
aWtleTAeFw0xODEwMzAwNDQ3MThaFw0yMzEwMjkwNDQ3MThaMBUxEzARBgNVBAMMCnJzYV9hcGlr
ZXkwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCwjBVK1CLppIwsFm7e+Fp85Hk1Mw2n
5Nc/DKT/pWhpJB8OdlpJA9iF23hrxfbXkrBfCkgvV4Ek4fY1byOnkA7hZq4dYTASCAm89oLwWDNm
0OGNh7E6T7/JoNtjtT0Gh8lJTvpUgHFGg3tiYCScAqul+fS6Rc8+5THk3L9zLzme6eqjkzwBx/ZV
XBIZlAwFkVKbfLFg51LiVoOUz6zXD7nAsMyNhKAgybvqulV07eGzafZ1IBgzpcw5qo0PAd1mTqfy
U+CK9hVeNPPspT16qQWd5xa+fa6BEjuGCumVnFLTbSTRAF5h3QAfvMlkpLdejlXJwvTVQ79Zg5C8
Hu/yWB7tOJBncIKue7KSpwn+vkMws79wpAB5mL4tD3kVCDf2Og7wbtt87v5rcazxF7eZFbsADzHV
oSftdkw5S7iXgh82/CHbRXhzPfG8Zd2v1ksW+Bfnn3czEIMGOSJrKfMbyCYtVMihoi0/L6SHA7++
N9aRrQvfK9PeXnlHgf8pErGUdpjnwdV0tu5atSgf/iBuRgVgUL6t6MFbnBsTQUmZYiQRcsqxOVdy
yfp4DOLgFHGJ1D/isgR/ypalIXMmhuK8GdZ7hukEDX2Dc3js8OkPnFLq6Ps4NIGESfbZSeyINoZX
5GGxdgD/GpokKMHr5bsI3TQujCvzuxShPhUArzCs6TgPmwIDAQABo0IwQDAdBgNVHQ4EFgQUyNoW
eeLVSzVybz7gcZnZlj01cv4wHwYDVR0jBBgwFoAUyNoWeeLVSzVybz7gcZnZlj01cv4wDQYJKoZI
hvcNAQEMBQADggIBADuwEh31OI66oSMB6a79Pd6WSqiyD2NBskdRF7st7CRP5vqeH4P/4srNFAqC
9CjsOmXmSpZFckYQ4zgtqnVQBY7jQlCuSHmg8/Lr1qIzRsMvQmhvp6DJ+bEfQgqcJ+a6tR9cH6hD
VahoMZDEpt3J0fIp30z+O7wJ03K6q5Di/rNey6Ac3GoZwlCi8OFCTmwihcn56I+ssxAqzlq53hzO
iBLLmcMTrWSJWePPkYEhrbBxywg1qJRRGWwkfr1dbRZ22umLHU0R/QdK+jQtqyzghqJpd3T/lHzK
uzAsa0s1R+qMqurKu6mulcLp/XmZpY+Fm4T0WRXzcZBf9trkCSO2Z3VvkCTeGu/WAi3UQpx4HfGr
x02m/h8CHCPPO+PKYthpvSR+0jmiVBaaBo029UG0i2oYBTckng2sy0fx0E+rHnR7pk5Worv8BMm5
sewPUkDDJMZhLtm/bd/VxlI/b56vEA7HvupSWzc7xXV8lZOHVEUAotrlXz+Je2MkEEQIDnYUOYhw
78yFMJJddK9tJVRy8tr8I2j6Zi62jQp/Zltq5JOwpOw/9poovd9wgeRBjuFnscoR/YWrNdPjsjpJ
g/CCb6mthz4R2Mu4enD1YghW7w5darrlUHaYAk+SnwWhMwDwZWWfrVNeEaNq/t/gRm/Ljy+Of3lA
nztA1PrT4bk1KvZX"; // Replace with real base64 string (from your `str1`)
            string publicKeyXml = $"<RSAKeyValue><Modulus>{rsaModulus}</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

            // Encrypt RANDOMNO1 using RSA
            byte[] encryptedRANDOMNO1 = EncryptRSA(Encoding.UTF8.GetBytes(RANDOMNO1), publicKeyXml);
            string ENCR_KEY = Convert.ToBase64String(encryptedRANDOMNO1);

            // Prepare the JSON data  //SBIN0003060

            var json = $@"{{
                ""tranRefNo"": ""202401081032010"",
                ""amount"": ""1.00"",
                ""senderAcctNo"": ""000405002777"",
                ""beneAccNo"": ""000405001611"",
                ""beneName"": ""PratikMundhe"",
                ""beneIFSC"": ""SBIN0003060"",
                ""narration1"": ""NEFT transaction"",
                ""narration2"": ""PritamGadekar"",
                ""crpId"": ""SESPRODUCT"",
                ""crpUsr"": ""389018"",
                ""aggrId"": ""XXX"",
                ""aggrName"": ""XXX"",
                ""urn"": ""XXX"",
                ""txnType"": ""RGS"",
                ""WORKFLOW_REQD"": ""N""
            }}";

            //var json = $@"{{
            //    ""tranRefNo"": ""202401081032010"",
            //    ""amount"": ""1.00"",
            //    ""senderAcctNo"": ""000405002500"",
            //    ""beneAccNo"": ""000451000301"",
            //    ""beneName"": ""PratikMundhe"",
            //    ""beneIFSC"": ""DLXB0000092"",
            //    ""narration1"": ""NEFT transaction"",
            //    ""narration2"": ""PritamGadekar"",
            //    ""crpId"": ""SESPRODUCT"",
            //    ""crpUsr"": ""BAN339226"",
            //    ""aggrId"": ""MESCOMP0302"",
            //    ""aggrName"": ""CGMSC"",
            //    ""urn"": ""CGMSC123"",
            //    ""txnType"": ""RGS"",
            //    ""WORKFLOW_REQD"": ""N"",
            //    ""BENLEI"": """"
            //}}";

            string DATA = RANDOMNO2 + json;
            string ENCR_DATA = EncryptAES(DATA, RANDOMNO1, RANDOMNO2);

            string url = "https://apibankingonesandbox.icicibank.com/api/v1/composite-payment";

            string result = PostEncryptedData(url, ENCR_DATA, ENCR_KEY);
            return Ok(result);
        }

        public static RSA GetRsaFromXmlString(string xml)
        {
            var rsa = RSA.Create();
            rsa.FromXmlString(xml);
            return rsa;
        }

        private string GenerateRandomDigits(int length)
        {
            var rng = RandomNumberGenerator.Create();
            var buffer = new byte[length];
            rng.GetBytes(buffer);

            var sb = new StringBuilder();
            foreach (var b in buffer)
                sb.Append((b % 10).ToString());
            return sb.ToString().Substring(0, length);
        }

        //private byte[] EncryptRSA(byte[] data, string publicKeyXml)
        //{
        //    using (var rsa = new RSACryptoServiceProvider())
        //    {
        //        rsa.FromXmlString(publicKeyXml);
        //        return rsa.Encrypt(data, false); // PKCS#1 v1.5
        //    }
        //}

        public static byte[] EncryptRSA(byte[] data, string base64Cert)
        {
            // using RSA rsa = GetRsaFromBase64Certificate(base64Cert);

            string rsaXml = base64Cert;  // It’s already XML
            using RSA rsa = GetRsaFromXmlString(rsaXml);  // ✅ Correct method

            return rsa.Encrypt(data, RSAEncryptionPadding.Pkcs1);
        }

        //public static RSA GetRsaFromBase64Certificate(string base64Cert)
        //{
        //    byte[] certBytes = Convert.FromBase64String(base64Cert);
        //    var cert = new X509Certificate2(certBytes);
        //    return cert.GetRSAPublicKey();
        //}

        public static RSA GetRsaFromBase64Certificate(string base64Cert)
        {
            // Clean line breaks and whitespace
            base64Cert = base64Cert.Replace("\r", "").Replace("\n", "").Replace(" ", "").Trim();

            byte[] certBytes = Convert.FromBase64String(base64Cert);
            var cert = new X509Certificate2(certBytes);
            return cert.GetRSAPublicKey();
        }

        private string EncryptAES(string plainText, string key16, string iv16)
        {
            byte[] key = Encoding.UTF8.GetBytes(key16);
            byte[] iv = Encoding.UTF8.GetBytes(iv16);

            using (var aes = Aes.Create())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = key;
                aes.IV = iv;

                using var encryptor = aes.CreateEncryptor();
                byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                byte[] cipherBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
                return Convert.ToBase64String(cipherBytes);
            }
        }

        private string PostEncryptedData(string url, string encryptedData, string encryptedKey)
        {
            var request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = "POST";
            request.ContentType = "application/json";
            request.Headers["apikey"] = encryptedKey;
            request.Headers["x-priority"] = "0010";

            byte[] data = Encoding.UTF8.GetBytes(encryptedData);
            request.ContentLength = data.Length;

            using (var stream = request.GetRequestStream())
            {
                stream.Write(data, 0, data.Length);
            }

            using var response = (HttpWebResponse)request.GetResponse();
            using var reader = new StreamReader(response.GetResponseStream());
            return reader.ReadToEnd();
        }
    }
}
