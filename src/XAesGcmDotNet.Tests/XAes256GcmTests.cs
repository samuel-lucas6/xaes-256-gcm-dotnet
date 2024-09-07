using System.Security.Cryptography;

namespace XAesGcmDotNet.Tests;

[TestClass]
public class XAes256GcmTests
{
    // https://github.com/C2SP/C2SP/blob/main/XAES-256-GCM.md#test-vectors
    public static IEnumerable<object[]> TestVectors()
    {
        yield return
        [
            "ce546ef63c9cc60765923609b33a9a1974e96e52daf2fcf7075e2271",
            "584145532d3235362d47434d",
            "4142434445464748494a4b4c4d4e4f505152535455565758",
            "0101010101010101010101010101010101010101010101010101010101010101",
            ""
        ];
        yield return
        [
            "986ec1832593df5443a179437fd083bf3fdb41abd740a21f71eb769d",
            "584145532d3235362d47434d",
            "4142434445464748494a4b4c4d4e4f505152535455565758",
            "0303030303030303030303030303030303030303030303030303030303030303",
            "633273702e6f72672f584145532d3235362d47434d"
        ];
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return [ XAes256Gcm.TagSize, 1, XAes256Gcm.NonceSize, XAes256Gcm.KeySize, 0 ];
        yield return [ XAes256Gcm.TagSize, 0, XAes256Gcm.NonceSize + 1, XAes256Gcm.KeySize, 0 ];
        yield return [ XAes256Gcm.TagSize, 0, XAes256Gcm.NonceSize - 1, XAes256Gcm.KeySize, 0 ];
        yield return [ XAes256Gcm.TagSize, 0, XAes256Gcm.NonceSize, XAes256Gcm.KeySize + 1, 0 ];
        yield return [ XAes256Gcm.TagSize, 0, XAes256Gcm.NonceSize, XAes256Gcm.KeySize - 1, 0 ];
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, XAes256Gcm.KeySize);
        Assert.AreEqual(24, XAes256Gcm.NonceSize);
        Assert.AreEqual(16, XAes256Gcm.TagSize);
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Encrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        Span<byte> c = stackalloc byte[ciphertext.Length / 2];
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);

        XAes256Gcm.Encrypt(c, p, n, k, ad);

        Assert.AreEqual(ciphertext, Convert.ToHexString(c).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Encrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, int associatedDataSize)
    {
        var c = new byte[ciphertextSize];
        var p = new byte[plaintextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];
        var ad = new byte[associatedDataSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => XAes256Gcm.Encrypt(c, p, n, k, ad));
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        Span<byte> p = stackalloc byte[plaintext.Length / 2];
        Span<byte> c = Convert.FromHexString(ciphertext);
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);

        XAes256Gcm.Decrypt(p, c, n, k, ad);

        Assert.AreEqual(plaintext, Convert.ToHexString(p).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Tampered(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        var p = new byte[plaintext.Length / 2];
        var parameters = new List<byte[]>
        {
            Convert.FromHexString(ciphertext),
            Convert.FromHexString(nonce),
            Convert.FromHexString(key),
            Convert.FromHexString(associatedData)
        };

        foreach (var param in parameters.Where(param => param.Length > 0)) {
            param[0]++;
            Assert.ThrowsException<AuthenticationTagMismatchException>(() => XAes256Gcm.Decrypt(p, parameters[0], parameters[1], parameters[2], parameters[3]));
            param[0]--;
        }
        Assert.IsTrue(p.SequenceEqual(new byte[p.Length]));
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Decrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, int associatedDataSize)
    {
        var p = new byte[plaintextSize];
        var c = new byte[ciphertextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];
        var ad = new byte[associatedDataSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => XAes256Gcm.Decrypt(p, c, n, k, ad));
    }
}
