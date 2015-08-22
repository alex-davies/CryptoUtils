using Ink.Utils.Encryption;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Threading.Tasks;

namespace Ink.Utils.Tests.Unit.Encryption
{
    [TestClass]
    public class HasherTests
    {
        [TestMethod]
        public async Task hash_should_generate_random_salt()
        {
            const string textToHash = "some text of mine";
            var hasher = new Hasher();

            var hash1 = hasher.Hash(textToHash);
            Assert.IsTrue(hash1.Length > 1);

            var hash2 = hasher.Hash(textToHash);

            Assert.AreNotEqual(hash1, hash2);
        }

        [TestMethod]
        public async Task when_hash_correct_check_hash_should_be_true()
        {
            const string textToHash = "some text of mine";
            var hasher = new Hasher();

            var hash = hasher.Hash("some text of mine");
            
            Assert.IsTrue(hasher.CheckHash(textToHash, hash));
        }

        [TestMethod]
        public async Task when_hash_incorrect_check_hash_should_be_true()
        {
            const string textToHash = "some text of mine";
            var hasher = new Hasher();

            var hash = hasher.Hash(textToHash);

            Assert.IsFalse(hasher.CheckHash("some other text", hash));
        }
       
    }
}