using System;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace EncryptedAssemblies.Starter.Cryptography
{
    internal static class CryptographyHelper
    {
        /// <summary>
        /// Зашифровывает строку.
        /// </summary>
        /// <param name="source">Исходные данные.</param>
        /// <param name="password">Ключ шифрования.</param>
        /// <returns></returns>
        public static CryptedData Encrypt(byte[] source, SecureString password)
        {
            byte[] iv = AesCryptography.CreateIv();
            byte[] key = GetKey(password);
            byte[] encrypted = AesCryptography.Encrypt(source, key, iv);

            return new CryptedData()
            {
                EncryptedSource = encrypted,
                IV = iv
            };
        }

        /// <summary>
        /// Расшифровывает данные.
        /// </summary>
        /// <param name="data">Данные, которые необходимо расшифровать.</param>
        /// <param name="password">Пароль шифрования.</param>
        /// <returns>Расшифрованные данные.</returns>
        public static byte[] Decrypt(CryptedData data, SecureString password)
        {
            byte[] key = GetKey(password);
            byte[] decrypted = AesCryptography.Decrypt(data.EncryptedSource, key, data.IV);
            return decrypted;
        }

        /// <summary>
        /// Дополняет длину ключа при необходимости.
        /// </summary>
        /// <param name="key">Ключ, который необходимо дополнить.</param>
        /// <returns></returns>
        private static byte[] GetKey(SecureString key)
        {
            using (InsecureString insecure = new InsecureString(key))
            {
                using (SHA256Managed sha256 = new SHA256Managed())
                {
                    byte[] rawKey = new byte[key.Length];
                    int i = 0;
                    foreach (char c in insecure)
                    {
                        rawKey[i++] = Convert.ToByte(c);
                    }

                    byte[] hashedKey = sha256.ComputeHash(rawKey);
                    Array.Clear(rawKey, 0, rawKey.Length);

                    return hashedKey;
                }
            }
        }
    }
}
