using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.ComTypes;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Ink.Utils.Encryption
{
    public interface IEncryptor
    {
        /// <summary>
        /// Preferred size of the salt
        /// </summary>
        int SaltByteSize { get; }

        /// <summary>
        /// Encrypts the specified data.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <param name="salt">The salt.</param>
        /// <returns></returns>
        byte[] Encrypt(byte[] data, byte[] salt);

        /// <summary>
        /// Decrypts the specified data.
        /// </summary>
        /// <param name="encryptedData">The data.</param>
        /// <param name="salt">The salt.</param>
        /// <returns></returns>
        byte[] Decrypt(byte[] encryptedData, byte[] salt);
    }


    public static class IEncryptorExtensions
    {
        /// <summary>
        /// Encrypts the specified encryptedData using the given salt.
        /// </summary>
        /// <param name="value">The encryptedData.</param>
        /// <returns>The encrypted encoded with a generated salt</returns>
        public static string Encrypt(this IEncryptor encryptor, string data)
        {
            //lets securely generate our salt of an appropriate length
            var salt = new byte[encryptor.SaltByteSize];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(salt);
            }

            byte[] encryptedData = encryptor.Encrypt(Encoding.UTF8.GetBytes(data), salt);

            //encode our salt into hte encrypted data, so we can decrypt it easier later
            return string.Join(":", Convert.ToBase64String(salt), Convert.ToBase64String(encryptedData));
        }


        /// <summary>
        /// Decrypts the specified encryptedData using the given salt.
        /// </summary>
        /// <param name="encryptedValue">The encryptedData as a base64 encoded string.</param>
        /// <param name="salt">The salt as a base64 encoded string.</param>
        /// <returns>The original unencrypted data</returns>
        public static string Decrypt(this IEncryptor encryptor, string encryptedValue)
        {
            var splitEncryptedValue = encryptedValue.Split(':');
            if (splitEncryptedValue.Length != 2)
                throw new ArgumentException("encryptedValue is not in the correct format","encryptedValue");

            byte[] salt;
            byte[] encryptedBytes;

            try
            {
                salt = Convert.FromBase64String(splitEncryptedValue[0]);
                encryptedBytes = Convert.FromBase64String(splitEncryptedValue[1]);
            }
            catch (FormatException ex)
            {
                throw new ArgumentException("encryptedValue is not in the correct format", "encryptedValue", ex);
            }

            var decryptedBytes = encryptor.Decrypt(encryptedBytes, salt);

            return Encoding.UTF8.GetString(decryptedBytes);
        }
    }

    public class Encryptor : IEncryptor, IDisposable
    {

        /// <summary>
        /// when we need to pad salts to be of a specific size we
        /// hash them, but to hash them we need a salt.
        /// </summary>
        private static readonly byte[] paddingSalt = new byte[] {
            0x8C, 0xFC, 0xCF, 0xB9, 0x2D, 0x3E, 0x24, 0xCE, 
            0x0A, 0xD8, 0x98, 0x94, 0x2C, 0xBE, 0x07, 0xF1, 
            0xB1, 0x72, 0xEE, 0x72, 0x37, 0x68, 0xFC, 0x11, 
            0x33, 0x06, 0xC4, 0x6D, 0x7E, 0x66, 0xEA, 0xCE 
        };

        /// <summary>
        /// Size of our encryption key
        /// </summary>
        public static int KeyByteSize { get { return 32; } }
        
        /// <summary>
        /// Size of our salts
        /// </summary>
        public int SaltByteSize { get { return 16; } }

        private readonly byte[] _key;
        private readonly AesCryptoServiceProvider _cryptoProvider;

        /// <summary>
        /// An encryptor using the given pass word as the key
        /// </summary>
        /// <param name="password">password to use as the key</param>
        /// <param name="iterations">iterations to use in hash function to convert password into suitable key</param>
        public Encryptor(string password, int iterations = 10000)
        {
            //expand out the password to get some bytes.
            using (var rfc2898DeriveBytes = new Rfc2898DeriveBytes(password, paddingSalt, iterations))
            {
                _key = rfc2898DeriveBytes.GetBytes(KeyByteSize);
                _cryptoProvider = new AesCryptoServiceProvider { Padding = PaddingMode.ISO10126 };
            }
        }

        /// <summary>
        /// An encryptor using hte given key as the encryption key
        /// </summary>
        /// <param name="key"></param>
        public Encryptor(byte[] key, int iterations = 10000)
        {
            _key = PadBytes(key, KeyByteSize);
            _cryptoProvider = new AesCryptoServiceProvider { Padding = PaddingMode.ISO10126 };
        }


        /// <summary>
        /// Encrypts the specified data.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <param name="salt">The salt.</param>
        /// <returns></returns>
        public byte[] Encrypt(byte[] data, byte[] salt)
        {
            salt = PadBytes(salt, SaltByteSize);
            using (var encryptor = _cryptoProvider.CreateEncryptor(_key, salt))
            {
                return Transform(data, encryptor);
            }
        }

        /// <summary>
        /// Decrypts the specified data.
        /// </summary>
        /// <param name="encryptedData">The data.</param>
        /// <param name="salt">The salt.</param>
        /// <returns></returns>
        /// <exception cref="System.Security.Cryptography.CryptographicException">Thrown when encrypted data can not be decyrpted with the given key and salt</exception>
        public byte[] Decrypt(byte[] encryptedData, byte[] salt)
        {
            salt = PadBytes(salt, SaltByteSize);
            using (var decryptor = _cryptoProvider.CreateDecryptor(_key, salt))
            {
                return Transform(encryptedData, decryptor);
            }
        }

        protected byte[] Transform(byte[] buffer, ICryptoTransform transform)
        {
            using (var stream = new MemoryStream())
            {
                using (var cs = new CryptoStream(stream, transform, CryptoStreamMode.Write))
                {
                    cs.Write(buffer, 0, buffer.Length);
                }
                return stream.ToArray();
            }
        }

        public void Dispose()
        {
            _cryptoProvider.Dispose();
        }

        /// <summary>
        /// If the byte array is not of hte required length it will pass through a hash function to 
        /// ensure the length is correct
        /// </summary>
        /// <param name="bytes"></param>
        /// <param name="keySizeInBytes"></param>
        /// <returns></returns>
        private static byte[] PadBytes(byte[] bytes, int keySizeInBytes)
        {
            if (bytes.Length == keySizeInBytes)
                return bytes;

            //we will only do one iteration here, we are not interested in securely
            //generating our salt key, only to make sure its of a size the algorithm
            //will work with
            using (var rfc2898DeriveBytes = new Rfc2898DeriveBytes(bytes, paddingSalt, 1))
            {
                return rfc2898DeriveBytes.GetBytes(keySizeInBytes);
            }
        }
    }
}
