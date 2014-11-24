using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace EncryptedAssemblies.Starter.Cryptography
{
    public static class AesCryptography
    {
        /// <summary>
        /// Возвращает вектор инициализации.
        /// </summary>
        /// <returns></returns>
        internal static byte[] CreateIv()
        {
            using (AesManaged aes = new AesManaged())
            {
                aes.GenerateIV();
                return aes.IV;
            }
        }

        /// <summary>
        /// Зашифровывает данные.
        /// </summary>
        /// <param name="source">Данные.</param>
        /// <param name="key">Ключ шифрования.</param>
        /// <param name="iv">Вектор инициализации.</param>
        /// <returns>Зашифрованные данные.</returns>
        internal static byte[] Encrypt(byte[] source, byte[] key, byte[] iv)
        {
            Validate(source, key, iv);
            using (AesManaged aes = new AesManaged())
            {
                using (ICryptoTransform transform = aes.CreateEncryptor(key, iv))
                {
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, transform, CryptoStreamMode.Write))
                        {
                            cs.Write(source, 0, source.Length);
                        }
                        byte[] encryptedBytes = ms.ToArray();
                        return encryptedBytes;
                    }
                }
            }
        }

        /// <summary>
        /// Расшифровывает текст.
        /// </summary>
        /// <param name="source">Данные для расшифровки.</param>
        /// <param name="key">Ключ шифрования.</param>
        /// <param name="iv">Вектор инициализации.</param>
        /// <returns>Расшифрованные данные.</returns>
        internal static byte[] Decrypt(byte[] source, byte[] key, byte[] iv)
        {
            Validate(source, key, iv);
            using (AesManaged aes = new AesManaged())
            {
                using (ICryptoTransform transform = aes.CreateDecryptor(key, iv))
                {
                    using (MemoryStream ms = new MemoryStream(source))
                    {
                        using (CryptoStream cs = new CryptoStream(ms, transform, CryptoStreamMode.Read))
                        {
                            List<byte> bytes = new List<byte>(1024);
                            int b;
                            while ((b = cs.ReadByte()) != -1)
                            {
                                bytes.Add((byte)b);
                            }
                            return bytes.ToArray();
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Проверяет данные.
        /// </summary>
        /// <param name="source">Данные.</param>
        /// <param name="key">Ключ шифрования.</param>
        /// <param name="iv">Вектор инициализации.</param>
        private static void Validate(byte[] source, byte[] key, byte[] iv)
        {
            if (source == null)
            {
                throw new ArgumentNullException("source");
            }
            else if (source.Length == 0)
            {
                throw new ArgumentException("Данные не могут быть пустыми", "source");
            }
            if (key == null)
            {
                throw new ArgumentNullException("key");
            }
            else if (key.Length == 0)
            {
                throw new ArgumentException("Ключ не может быть пустым", "key");
            }
            if (key.Length.IsOneOf(16, 24, 32) == false)
            {
                throw new ArgumentException("Длина ключа должна быть 128, 192 или 256 бит (16, 24, 32 байта)", "key");
            }
            if (iv == null)
            {
                throw new ArgumentNullException("iv");
            }
            else if (iv.Length != 16)
            {
                throw new ArgumentException("Длина вектора инициализации должна быть 128 бит (16 байт)", "iv");
            }
        }

        public static bool IsOneOf<T>(this T value, params T[] values)
        {
            return value.IsOneOf(values as IEnumerable<T>);
        }

        public static bool IsOneOf<T>(this T value, IEnumerable<T> values)
        {
            if (values == null)
            {
                throw new ArgumentNullException("values");
            }
            foreach (T t in values)
            {
                if (Equals(t, value))
                {
                    return true;
                }
            }
            return false;
        }
    }
}
