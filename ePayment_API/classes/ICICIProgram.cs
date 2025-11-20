using Microsoft.SqlServer.Server;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Net.Http;
using System.Web;
using Newtonsoft.Json;
using ePayment_API.DTOs;
namespace ePayment_API.classes

{
    public class ICICIProgram
    {
        private static string invokeRequest(string data, string url, string method, string bankTransferType, string callName = "")
        {
            string _output = string.Empty;
            string _guid = Guid.NewGuid().ToString() + DateTime.Now.ToString("yyyy-MM-dd-HH:mm:ss");
            var _request = EncryptData(data.ToString());
            string httpUrl = url;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            ErrorLog(_guid, httpUrl, data, _request.ToString(), method, "");

            var httpWebRequest = (HttpWebRequest)WebRequest.Create(httpUrl);
            httpWebRequest.ContentType = "application/json";
            httpWebRequest.Headers.Add("apikey", "tqwr5u6KBKlFPydVYIe4AGSD0uHdnFES");

            if (bankTransferType.ToUpper() == "IMPS")
            {
                httpWebRequest.Headers.Add("x-priority", "0100");
            }
            else if (bankTransferType.ToUpper() == "NEFT")
            {
                httpWebRequest.Headers.Add("x-priority", "0010");
            }
            else if (bankTransferType.ToUpper() == "RTGS")
            {
                httpWebRequest.Headers.Add("x-priority", "0001");
            }


            httpWebRequest.Method = method;
            httpWebRequest.KeepAlive = false;

            using (var streamWriter = new StreamWriter(httpWebRequest.GetRequestStream()))
            {
                streamWriter.Write(_request);
                streamWriter.Flush();
            }

            string _resCode = string.Empty;
            string _decrypt = string.Empty;

            HttpWebResponse httpResponse = null;
            httpResponse = (HttpWebResponse)httpWebRequest.GetResponse();
            _resCode = Convert.ToString(httpResponse.StatusCode);
            using (var streamReader = new StreamReader(httpResponse.GetResponseStream()))
            {
                _output = streamReader.ReadToEnd();
            }

            ErrorLog(_guid, httpUrl, _output, _decrypt, method, _resCode);

            dynamic dataParse = Newtonsoft.Json.Linq.JObject.Parse(_output);

            string encryptedKey = dataParse.encryptedKey;
            string encryptedData = dataParse.encryptedData;

            byte[] _keyDecrypt = Convert.FromBase64String(encryptedKey);
            string _decryptKey = DecryptKey(_keyDecrypt);

            string _decryptData = DecryptData(encryptedData, _decryptKey);
            _decryptData = _decryptData.Replace("\\x{10}", string.Empty).Replace("\u000e", string.Empty).Replace("\u000f", string.Empty).Replace("\u0002", string.Empty).Replace("\u0006", string.Empty).Replace("\u0005", string.Empty).Replace("\u0003", string.Empty);

            char[] spearator = { '}' };
            string[] strlist = _decryptData.Split('}');
            _decryptData = strlist[0] + " }";

            ErrorLog(_guid, httpUrl, _output, _decryptData, method, _resCode);
            return _decryptData;
        }

        private static string DecryptKey(byte[] keyDecrypt)
        {
            X509Certificate2 certificate = getPrivateKey();
            if (certificate?.GetRSAPrivateKey() is RSA privateKey)
            {
                byte[] decryptedKeyBytes = privateKey.Decrypt(keyDecrypt, RSAEncryptionPadding.Pkcs1);
                return Convert.ToBase64String(decryptedKeyBytes);
            }
            else
            {
                throw new InvalidOperationException("The certificate does not contain a valid RSA private key.");
            }
        }

        public static X509Certificate2 getPublicKey()
        {
            //string _textURL = @"C:\\inetpub\\wwwroot\\rsa_apikey.txt";
            string _textURL = @"C:\\inetpub\\wwwroot\\STAR_dpdmis_in\\publicCertificate1.txt";

            X509Certificate2 cert2 = new X509Certificate2(_textURL);
            return cert2;
        }

        public static X509Certificate2 getPrivateKey()
        {
            //string _keyURL = @"C:\\inetpub\\wwwroot\\cgmsc15.pfx";
            string _keyURL = @"C:\\inetpub\\wwwroot\\STAR_dpdmis_in\\dpdmis.pfx";
            X509Certificate2 cert2 = new X509Certificate2(_keyURL, "123456", X509KeyStorageFlags.UserKeySet);

            if (cert2.PrivateKey == null)
            {
                throw new InvalidOperationException("The certificate does not contain a private key.");
            }
            return cert2;
        }

        private static string EncryptData(string data)
        {
            byte[] databyte1 = Encoding.UTF8.GetBytes(data);
            byte[] RANDOMNO = new byte[16];
            for (int i = 0; i < 16; i++)
            {
                RANDOMNO[i] = databyte1[i];
            }

            string encryptedKey = encryptRandomNo(RANDOMNO);

            AesManaged aes = new AesManaged();
            byte[] iv = aes.IV;

            byte[] ENCR_DATA = encryptSendData(data, RANDOMNO, iv);
            string encryptedData = Convert.ToBase64String(ENCR_DATA);

            Guid guid = Guid.NewGuid();

            var _parameterList = new Dictionary<string, object>
            {
                { "requestId", "req" },
                { "encryptedKey", encryptedKey },
                { "iv", Convert.ToBase64String(iv) },
                { "encryptedData", encryptedData },
                { "oaepHashingAlgorithm", "none" },
                { "service", "" },
                { "clientInfo", "" },
                { "optionalParam", "" }
            };

            var encodejson = JsonConvert.SerializeObject(_parameterList);
            return encodejson;
        }

        public static string encryptRandomNo(byte[] stringToEncrypt)
        {
            X509Certificate2 certificate = getPublicKey();
            var publicKey = certificate.PublicKey.Key;
            if (publicKey is RSA rsa)
            {
                byte[] cryptedData = rsa.Encrypt(stringToEncrypt, RSAEncryptionPadding.Pkcs1);
                return Convert.ToBase64String(cryptedData);
            }
            else
            {
                throw new InvalidCastException("Public key is not of type RSA.");
            }
        }

        public static byte[] encryptSendData(string plainText, byte[] Key, byte[] IV)
        {
            byte[] encrypted;
            using (AesManaged aes = new AesManaged())
            {
                ICryptoTransform encryptor = aes.CreateEncryptor(Key, IV);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter sw = new StreamWriter(cs))
                            sw.Write(plainText);

                        encrypted = ms.ToArray();
                    }
                }
            }
            return encrypted;
        }

        public static string DecryptKey(string encryptedKeyBase64)
        {
            byte[] encryptedKey = Convert.FromBase64String(encryptedKeyBase64);
            X509Certificate2 certificate = getPrivateKey();
            if (certificate?.GetRSAPrivateKey() is RSA privateKey)
            {
                byte[] decryptedKeyBytes = privateKey.Decrypt(encryptedKey, RSAEncryptionPadding.Pkcs1);
                return Convert.ToBase64String(decryptedKeyBytes);
            }
            else
            {
                throw new InvalidOperationException("The certificate does not contain a valid RSA private key.");
            }
        }

        private static string DecryptData(string encryptedDataBase64, string decryptedKeyBase64)
        {
            byte[] encryptedData = Convert.FromBase64String(encryptedDataBase64);
            byte[] decryptedKey = Convert.FromBase64String(decryptedKeyBase64);

            byte[] iv = new byte[16];
            Array.Copy(encryptedData, 0, iv, 0, 16);

            byte[] ciphertext = new byte[encryptedData.Length - 16];
            Array.Copy(encryptedData, 16, ciphertext, 0, ciphertext.Length);

            return AESDecrypt(Convert.ToBase64String(ciphertext), Convert.ToBase64String(decryptedKey), iv);
        }

        public static string AESDecrypt(string encryptedDataBase64, string decryptedKeyBase64, byte[] iv)
        {
            byte[] encryptedData = Convert.FromBase64String(encryptedDataBase64);
            byte[] key = Convert.FromBase64String(decryptedKeyBase64);

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Padding = PaddingMode.PKCS7;
                aes.Mode = CipherMode.CBC;
                using (ICryptoTransform decryptor = aes.CreateDecryptor())
                using (MemoryStream ms = new MemoryStream(encryptedData))
                using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                using (StreamReader sr = new StreamReader(cs))
                {
                    return sr.ReadToEnd();
                }
            }
        }



        private static void ErrorLog(string guid, string httpUrl, string output, string decrypt, string method, string resCode)
        {
            Console.WriteLine(output);
        }

        public static string DecryptApiResponse(string apiResponse)
        {
            dynamic dataParse = Newtonsoft.Json.Linq.JObject.Parse(apiResponse);

            // Check if the expected fields are present
            if (dataParse.encryptedKey == null || dataParse.encryptedData == null)
            {
                // Return the raw response or a message
                return apiResponse;
            }

            string encryptedKey = dataParse.encryptedKey;
            string encryptedData = dataParse.encryptedData;

            string decryptedKey = DecryptKey(Convert.FromBase64String(encryptedKey));
            string decryptedData = DecryptData(encryptedData, decryptedKey);

            return decryptedData;
        }

        public string paraIMPS(PaymentRequestDTO request)
        {
            string bankTransferType = "IMPS";

            string currentDateTime = DateTime.Now.ToString("yyyyMMddHHmmss");
            var _parameterList = new Dictionary<string, object>
             {
                 { "amount", request.Amount },
                 { "senderName", request.SenderName },
                 { "bcID", request.BcID },
                 { "tranRefNo", request.TranRefNo },
                 { "localTxnDtTime", currentDateTime },
                 { "beneIFSC", request.BeneIFSC },
                 { "mobile", request.Mobile },
                 { "beneAccNo", request.BeneAccNo },
                 { "retailerCode", request.RetailerCode },
                 { "passCode", request.PassCode },
                 { "paymentRef", request.PaymentRef },
                 { "crpId", request.CrpId },
                 { "crpUsr", request.CrpUsr },
                 { "aggrId", request.AggrId },
                 //{ "bnfId", request.BnfId },
                 //{ "urn", request.Urn },
                 //{ "aggrName", request.AggrName }
             };

            var payload = JsonConvert.SerializeObject(_parameterList);
            string mandate = invokeRequest(payload, "https://apibankingonesandbox.icicibank.com/api/v1/composite-payment", "POST", bankTransferType);
            Console.WriteLine(mandate);
            return mandate;
        }

        public string paraNEFT(PaymentRequestNEFT_DTO request)
        {
            string bankTransferType = "NEFT";
            string currentDateTime = DateTime.Now.ToString("yyyyMMddHHmmss");

            var parameterList = new Dictionary<string, object?>
    {
        { "tranRefNo", request.TranRefNo },
        { "amount", request.Amount },
        { "senderAcctNo", request.SenderAcctNo },
        { "beneAccNo", request.BeneAccNo },
        { "beneName", request.BeneName },
        { "beneIFSC", request.BeneIFSC },
        { "narration1", request.Narration1 },
        { "narration2", request.Narration2 },
        { "crpId", request.CrpId },
        { "crpUsr", request.CrpUsr },
        { "aggrId", request.AggrId },
        { "aggrName", request.AggrName },
        { "urn", request.Urn },
        { "txnType", request.TxnType },   // e.g., "RGS" for NEFT
        { "WORKFLOW_REQD", request.WORKFLOW_REQD },
        //{ "BENLEI", request.BENLEI },
        { "localTxnDtTime", currentDateTime }
    };

            var payload = JsonConvert.SerializeObject(parameterList);

            string response = invokeRequest(
                payload,
                "https://apibankingonesandbox.icicibank.com/api/v1/composite-payment",
                "POST",
                bankTransferType
            );

            Console.WriteLine(response);
            return response;
        }

        public string paraRTGS(PaymentRequestRTGS_DTO request)
        {
            string bankTransferType = "RTGS";

            var parameterList = new Dictionary<string, object?>
    {
        { "AGGRID", request.AGGRID },
        { "CORPID", request.CORPID },
        { "USERID", request.USERID },
        { "URN", request.URN },
        { "AGGRNAME", request.AGGRNAME },
        { "UNIQUEID", request.UNIQUEID },
        { "DEBITACC", request.DEBITACC },
        { "CREDITACC", request.CREDITACC },
        { "IFSC", request.IFSC },
        { "AMOUNT", request.AMOUNT },
        { "CURRENCY", request.CURRENCY },
        { "TXNTYPE", request.TXNTYPE },   // "RTG" for RTGS
        { "PAYEENAME", request.PAYEENAME },
        { "REMARKS", request.REMARKS },
        { "WORKFLOW_REQD", request.WORKFLOW_REQD },
        { "BENLEI", request.BENLEI }
    };

            var payload = JsonConvert.SerializeObject(parameterList);

            string response = invokeRequest(
                payload,
                "https://apibankingonesandbox.icicibank.com/api/v1/composite-payment",
                "POST",
                bankTransferType
            );

            Console.WriteLine(response);
            return response;
        }




    }
}
