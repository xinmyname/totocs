using System.Text;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

public class OneTimePassword {

    private static readonly DateTime Origin = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
    private readonly byte[] _sharedSecret;
    private readonly int _ttlSeconds;

    public OneTimePassword(byte[] sharedSecret, int ttlSeconds = 30) {
        _sharedSecret = sharedSecret;
        _ttlSeconds = ttlSeconds;
    }

    public OneTimePassword(string sharedSecret, int ttlSeconds = 30) 
        : this(Encoding.UTF8.GetBytes(sharedSecret), ttlSeconds) {            
    }

    public int Generate() {
        return TOTP() % 1000000;
    }

    private int TOTP() {
        long to = UnixEpoch();
        long ti = _ttlSeconds;
        long tc = (UnixTime(DateTime.UtcNow) - to) / ti;

        return HOTP(_sharedSecret, BitConverter.GetBytes(tc));
    }

    private static int HOTP(byte[] k, byte[] c) {
        return Truncate(HMAC(k, c)) & 0x7FFFFFFF;
    }

    private static byte[] XOR(byte[] d, byte v) {
        return d.Select(x => (byte)(x^v)).ToArray();
    }

    private static byte[] Concatenate(byte[] a, byte[] b) {
        return a.Concat(b).ToArray();
    }

    private static byte[] SHA1(byte[] d) {
        var sha1 = new SHA1Managed();
        return sha1.ComputeHash(d);
    }

    private static byte[] HMAC(byte[] k, byte[] m) {
        return Concatenate(SHA1(XOR(k, 0x5c)), Concatenate(XOR(k, 0x36), m));
    }

    private static int Truncate(byte[] d)
    {
        var v = new byte[4];
        int stride = d.Length / 4;
        int remnant = d.Length % 4;

        for (int y = 0; y < 4; y++)
        {
            int o = y * stride;

            for (int x = 0; x < stride; x++)
                v[y] ^= d[o + x];
        }

        for (int x = 0; x < remnant; x++)
            v[x] ^= d[stride*4 + x];

        return BitConverter.ToInt32(v, 0);
    }

    private static long UnixTime(DateTime date) {
        TimeSpan diff = date.ToUniversalTime() - Origin;
        return (long) diff.TotalSeconds;
    }

    private static long UnixEpoch() {
        return UnixTime(Origin);
    }
}