using System.Security.Cryptography;

public static class Hash
{
    // RSA.Create() is mentioned in a comment only.
    public static byte[] Digest(byte[] data) => SHA256.HashData(data);
    public static byte[] Random(int n) => RandomNumberGenerator.GetBytes(n);
}