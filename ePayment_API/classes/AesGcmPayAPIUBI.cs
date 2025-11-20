using System;
using System.Text;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;



namespace ePayment_API.classes
{
    class AesGcmPayAPIUBI
    {
        // Parameters
        private const int KeyLength = 32; //Bytes
        private const int IvLength = 16;   //Bytes 
        private const int SaltLength = 16; //Bytes
        private const int TagLength = 128; //Bits
        private const int IterationCount = 65536;
        private static readonly Encoding Charset = Encoding.UTF8;

        // ENCRYPT
        public static string Encrypt(string plaintext, string password)
        {
            // Generate random IV and salt
            SecureRandom rng = new SecureRandom();
            byte[] iv = new byte[IvLength];
            byte[] salt = new byte[SaltLength];
            rng.NextBytes(iv);
            rng.NextBytes(salt);

            // Derive key using PBKDF2WithHmacSHA256
            byte[] key = Rfc2898DeriveBytes.Pbkdf2(password, salt, IterationCount, HashAlgorithmName.SHA256, KeyLength);

            // Initialize AES-GCM and get ciphertext
            byte[] plaintextBytes = Charset.GetBytes(plaintext);

            GcmBlockCipher cipher = new GcmBlockCipher(new AesEngine());
            AeadParameters parameters = new AeadParameters(new KeyParameter(key), TagLength, iv, null);
            cipher.Init(true, parameters);

            byte[] outBuf = new byte[cipher.GetOutputSize(plaintextBytes.Length)];
            int len = cipher.ProcessBytes(plaintextBytes, 0, plaintextBytes.Length, outBuf, 0);
            len += cipher.DoFinal(outBuf, len);
            byte[] cipherFin = new byte[len];
            Array.Copy(outBuf, 0, cipherFin, 0, len);

            // Combine IV, ciphertext, salt
            byte[] fullString = new byte[IvLength + cipherFin.Length + SaltLength];
            int offset = 0;
            Array.Copy(iv, 0, fullString, offset, IvLength); offset += IvLength;
            Array.Copy(cipherFin, 0, fullString, offset, cipherFin.Length); offset += cipherFin.Length;
            Array.Copy(salt, 0, fullString, offset, SaltLength);

            // Base64 encode
            string encryptedString = Convert.ToBase64String(fullString);

            return encryptedString;
        }


        // DECRYPT
        public static string Decrypt(string iencryptedString, string password)
        {
            // Decode base64 to byte array
            byte[] ifullString = Convert.FromBase64String(iencryptedString);

            // Extract IV, Salt, Cipher+Tag
            byte[] iv = new byte[IvLength];
            Array.Copy(ifullString, 0, iv, 0, IvLength);

            byte[] salt = new byte[SaltLength];
            Array.Copy(ifullString, ifullString.Length - SaltLength, salt, 0, SaltLength);

            int icipherFinLen = ifullString.Length - IvLength - SaltLength;
            byte[] icipherFin = new byte[icipherFinLen];
            Array.Copy(ifullString, IvLength, icipherFin, 0, icipherFinLen);

            // Derive key using PBKDF2WithHmacSHA256
            byte[] key = Rfc2898DeriveBytes.Pbkdf2(password, salt, IterationCount, HashAlgorithmName.SHA256, KeyLength);

            // Initialize AES-GCM and decrypt
            GcmBlockCipher cipher = new GcmBlockCipher(new AesEngine());
            AeadParameters parameters = new AeadParameters(new KeyParameter(key), TagLength, iv, null);
            cipher.Init(false, parameters);

            byte[] outBuf = new byte[cipher.GetOutputSize(icipherFin.Length)];
            int len = 0;
            len = cipher.ProcessBytes(icipherFin, 0, icipherFin.Length, outBuf, 0);
            len += cipher.DoFinal(outBuf, len);

            byte[] plaintextBytes = new byte[len];
            Array.Copy(outBuf, 0, plaintextBytes, 0, len);

            string decryptedString = Charset.GetString(plaintextBytes);

            return decryptedString;
        }
    }
}
