using System.Security.Cryptography;

public static class Keys
{
    public static void Make()
    {
        using var rsa = RSA.Create(3072);
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    }
}