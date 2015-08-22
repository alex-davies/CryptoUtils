using Ink.Utils.Encryption;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Linq;

namespace Ink.Utils.Tests.Unit.Encryption
{
    [TestClass]
    public class EncryptorTests
    {
        [TestMethod]
        public async Task encrypted_string_should_be_able_to_decrypt()
        {
            const string textToEncrypt = "some text of mine";
            var encryptor = new Encryptor("my key");

            var encryptedText = encryptor.Encrypt(textToEncrypt);
            Assert.AreNotEqual(textToEncrypt, encryptedText);

            var decryptedText = encryptor.Decrypt(encryptedText);
            Assert.AreEqual(textToEncrypt, decryptedText);
        }


        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public async Task incorrect_encrypted_string_format_should_throw()
        {
            const string textToEncrypt = "some text of mine";
            var encryptor = new Encryptor("my key");

            var decryptedText = encryptor.Decrypt("This is not the correct format");
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public async Task incorrect_encrypted_value_should_throw()
        {
            const string textToEncrypt = "some text of mine";
            var encryptor = new Encryptor("my key");

            //correct format, but not cryptographically correct
            var decryptedText = encryptor.Decrypt("c29tZXRoaW5n:c29tZXRoaW5n");
        }

        [TestMethod]
        public async Task short_bytes_should_be_padded()
        {
            var data = new byte[] { 0xAA };
            var salt = new byte[]{0xAA};
            var encryptor = new Encryptor("my key");

            var encryptedBytes = encryptor.Encrypt(data, salt);
            var decryptedData = encryptor.Decrypt(encryptedBytes, salt);

            Assert.IsTrue(data.SequenceEqual(decryptedData));
        }
    }
}