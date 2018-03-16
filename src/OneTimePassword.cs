using System.Text;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

public struct OneTimePassword {
    
    public int Value { get; set; }
    public long Expires { get; set;}

    public override string ToString() {
        DateTime expiry = OneTimePasswordFactory.Origin.AddSeconds(Expires);
        return $"{Value:000000} - {expiry}";
    }
}

public class OneTimePasswordFactory {

    public static readonly DateTime Origin = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    private readonly byte[] _sharedSecret;
    private readonly int _ttlSeconds;

    public OneTimePasswordFactory(byte[] sharedSecret, int ttlSeconds = 30) {
        _sharedSecret = sharedSecret;
        _ttlSeconds = ttlSeconds;
    }

    public OneTimePasswordFactory(string sharedSecret, int ttlSeconds = 30) 
        : this(Encoding.UTF8.GetBytes(sharedSecret), ttlSeconds) {            
    }

    public OneTimePassword Generate() {

        DateTime now = DateTime.UtcNow;
        long to = UnixTime(Origin);
        long ti = _ttlSeconds;
        long un = UnixTime(now);
        long tc = (un - to) / ti;

        return new OneTimePassword {
            Value = HOTP(_sharedSecret, BitConverter.GetBytes(tc)) % 1000000,
            Expires = (tc + 1) * ti 
        };
    }

    private static int HOTP(byte[] key, byte[] counter) {
        return Truncate(HMAC(key, counter)) & 0x7FFFFFFF;
    }

    private static byte[] XOR(byte[] data, byte value) {
        return data.Select(x => (byte)(x^value)).ToArray();
    }

    private static byte[] Concatenate(byte[] data1, byte[] data2) {
        return data1.Concat(data2).ToArray();
    }

    private static byte[] SHA1(byte[] data) {
        var sha1 = new SHA1Managed();
        return sha1.ComputeHash(data);
    }

    private static byte[] HMAC(byte[] key, byte[] message) {
        return Concatenate(SHA1(XOR(key, 0x5c)), Concatenate(XOR(key, 0x36), message));
    }

    private static int Truncate(byte[] data) {
        var result = new byte[4];
        int stride = data.Length / 4;
        int remnant = data.Length % 4;

        for (int y = 0; y < 4; y++) {

            int o = y * stride;

            for (int x = 0; x < stride; x++)
                result[y] ^= data[o + x];
        }

        for (int x = 0; x < remnant; x++)
            result[x] ^= data[stride*4 + x];

        return BitConverter.ToInt32(result, 0);
    }

    private static long UnixTime(DateTime date) {
        TimeSpan diff = date.ToUniversalTime() - Origin;
        return (long) diff.TotalSeconds;
    }
}