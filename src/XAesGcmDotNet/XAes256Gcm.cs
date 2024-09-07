using System.Security.Cryptography;

namespace XAesGcmDotNet;

public static class XAes256Gcm
{
    public const int KeySize = 32;
    public const int NonceSize = 24;
    public const int TagSize = 16;
    private const int BlockSize = 16;

    public static bool IsSupported()
    {
        return AesGcm.IsSupported;
    }

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        if (!IsSupported()) { throw new PlatformNotSupportedException("AES-GCM is not supported on this platform."); }
        if (ciphertext.Length != plaintext.Length + TagSize) { throw new ArgumentOutOfRangeException(nameof(ciphertext), ciphertext.Length, $"{nameof(ciphertext)} must be {plaintext.Length + TagSize} bytes long."); }
        if (nonce.Length != NonceSize) { throw new ArgumentOutOfRangeException(nameof(nonce), nonce.Length, $"{nameof(nonce)} must be {NonceSize} bytes long."); }
        if (key.Length != KeySize) { throw new ArgumentOutOfRangeException(nameof(key), key.Length, $"{nameof(key)} must be {KeySize} bytes long."); }

        Span<byte> subkey = stackalloc byte[KeySize];
        DeriveSubkey(subkey, nonce[..12], key);

        using var gcm = new AesGcm(subkey, TagSize);
        gcm.Encrypt(nonce[12..], plaintext, ciphertext[..^TagSize], ciphertext[^TagSize..], associatedData);
        CryptographicOperations.ZeroMemory(subkey);
    }

    private static void DeriveSubkey(Span<byte> subkey, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key)
    {
        Span<byte> message = stackalloc byte[BlockSize];
        Span<byte> k1 = stackalloc byte[BlockSize];
        message.Clear();
        using var aes = Aes.Create();
        aes.Key = key.ToArray();
        aes.EncryptEcb(message, k1, PaddingMode.None);

        // Adapted from https://github.com/bcgit/bc-csharp/blob/685cdb67590ae9af250326c0eb086f97ad5cd60f/crypto/src/crypto/macs/CMac.cs#L121
        byte msb = 0;
        for (int i = k1.Length - 1; i >= 0; i--) {
            byte b = k1[i];
            k1[i] = (byte)((b << 1) | msb);
            msb = (byte)((b >> 7) & 1);
        }
        k1[^1] ^= (byte)(0x87 >> ((1 - msb) << 3));

        Span<byte> xoredMessage = stackalloc byte[BlockSize];
        message[1] = 0x01;
        message[2] = 0x58;
        nonce.CopyTo(message[^12..]);
        for (int i = 0; i < message.Length; i++) {
            xoredMessage[i] = (byte)(message[i] ^ k1[i]);
        }
        aes.EncryptEcb(xoredMessage, subkey[..BlockSize], PaddingMode.None);

        message[1] = 0x02;
        for (int i = 0; i < message.Length; i++) {
            xoredMessage[i] = (byte)(message[i] ^ k1[i]);
        }
        aes.EncryptEcb(xoredMessage, subkey[BlockSize..], PaddingMode.None);

        CryptographicOperations.ZeroMemory(message);
        CryptographicOperations.ZeroMemory(k1);
        CryptographicOperations.ZeroMemory(xoredMessage);
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        if (!IsSupported()) { throw new PlatformNotSupportedException("AES-GCM is not supported on this platform."); }
        if (ciphertext.Length < TagSize) { throw new ArgumentOutOfRangeException(nameof(ciphertext), ciphertext.Length, $"{nameof(ciphertext)} must be at least {TagSize} bytes long."); }
        if (plaintext.Length != ciphertext.Length - TagSize) { throw new ArgumentOutOfRangeException(nameof(plaintext), plaintext.Length, $"{nameof(plaintext)} must be {ciphertext.Length - TagSize} bytes long."); }
        if (nonce.Length != NonceSize) { throw new ArgumentOutOfRangeException(nameof(nonce), nonce.Length, $"{nameof(nonce)} must be {NonceSize} bytes long."); }
        if (key.Length != KeySize) { throw new ArgumentOutOfRangeException(nameof(key), key.Length, $"{nameof(key)} must be {KeySize} bytes long."); }

        Span<byte> subkey = stackalloc byte[KeySize];
        DeriveSubkey(subkey, nonce[..12], key);

        try {
            using var gcm = new AesGcm(subkey, TagSize);
            gcm.Decrypt(nonce[12..], ciphertext[..^TagSize], ciphertext[^TagSize..], plaintext, associatedData);
        }
        finally {
            CryptographicOperations.ZeroMemory(subkey);
        }
    }
}
