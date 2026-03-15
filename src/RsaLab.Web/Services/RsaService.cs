using System.Diagnostics;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using RsaLab.Web.Models;

namespace RsaLab.Web.Services;

public class RsaService
{
    private static readonly int[] FermatCandidates = [65537, 257, 17, 5, 3];

    public RsaResult Run(RsaRequest request)
    {
        var keyTimer = Stopwatch.StartNew();
        var (p, q, n) = GenerateModulus(request.DigitsInN);
        var phi = (p - 1) * (q - 1);
        var e = SelectExponent(phi);
        var d = ModInverse(e, phi);
        var blockSize = CalculateBlockSize(n);
        keyTimer.Stop();

        var plaintextBytes = Encoding.UTF8.GetBytes(request.PlainText);

        var encryptTimer = Stopwatch.StartNew();
        var encrypted = Encrypt(plaintextBytes, e, n, blockSize);
        encryptTimer.Stop();

        var decryptTimer = Stopwatch.StartNew();
        var decryptedBytes = Decrypt(encrypted, d, n, blockSize, plaintextBytes.Length);
        decryptTimer.Stop();

        return new RsaResult
        {
            P = p,
            Q = q,
            N = n,
            Phi = phi,
            E = e,
            D = d,
            BlockSizeBytes = blockSize,
            CipherBlocks = encrypted,
            DecryptedText = Encoding.UTF8.GetString(decryptedBytes),
            KeyGenerationTime = keyTimer.Elapsed,
            EncryptionTime = encryptTimer.Elapsed,
            DecryptionTime = decryptTimer.Elapsed
        };
    }

    public static int EstimateSecurityBits(BigInteger n)
    {
        var bits = (int)Math.Ceiling(BigInteger.Log(n, 2));
        return bits;
    }

    private static (BigInteger p, BigInteger q, BigInteger n) GenerateModulus(int digitsInN)
    {
        var minN = BigInteger.Pow(10, digitsInN - 1);
        var maxN = BigInteger.Pow(10, digitsInN) - 1;
        var pDigits = digitsInN / 2;
        var qDigits = digitsInN - pDigits;

        while (true)
        {
            var p = GeneratePrimeWithDigits(pDigits);
            var q = GeneratePrimeWithDigits(qDigits);
            if (p == q)
            {
                continue;
            }

            var n = p * q;
            if (n >= minN && n <= maxN)
            {
                return (p, q, n);
            }
        }
    }

    private static BigInteger GeneratePrimeWithDigits(int digits)
    {
        var min = BigInteger.Pow(10, digits - 1);
        var max = BigInteger.Pow(10, digits) - 1;

        while (true)
        {
            var candidate = RandomOddBigInteger(min, max);
            if (IsProbablePrime(candidate, 30))
            {
                return candidate;
            }
        }
    }

    private static BigInteger RandomOddBigInteger(BigInteger min, BigInteger max)
    {
        var range = max - min + 1;
        var bytes = range.ToByteArray(isUnsigned: true, isBigEndian: true);
        BigInteger result;
        do
        {
            RandomNumberGenerator.Fill(bytes);
            result = new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
        } while (result >= range);

        var candidate = min + result;
        if (candidate.IsEven)
        {
            candidate += 1;
            if (candidate > max)
            {
                candidate -= 2;
            }
        }

        return candidate;
    }

    public static bool IsProbablePrime(BigInteger value, int witnesses)
    {
        if (value < 2)
            return false;
        if (value == 2 || value == 3)
            return true;
        if (value % 2 == 0)
            return false;

        var d = value - 1;
        var s = 0;
        while (d % 2 == 0)
        {
            d /= 2;
            s += 1;
        }

        var bytes = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        for (var i = 0; i < witnesses; i++)
        {
            BigInteger a;
            do
            {
                RandomNumberGenerator.Fill(bytes);
                a = new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
            } while (a < 2 || a >= value - 2);

            var x = BigInteger.ModPow(a, d, value);
            if (x == 1 || x == value - 1)
            {
                continue;
            }

            var continueWitness = false;
            for (var r = 1; r < s; r++)
            {
                x = BigInteger.ModPow(x, 2, value);
                if (x == value - 1)
                {
                    continueWitness = true;
                    break;
                }
            }

            if (continueWitness)
            {
                continue;
            }

            return false;
        }

        return true;
    }

    private static BigInteger SelectExponent(BigInteger phi)
    {
        foreach (var candidate in FermatCandidates)
        {
            if (BigInteger.GreatestCommonDivisor(candidate, phi) == 1)
            {
                return candidate;
            }
        }

        var e = new BigInteger(3);
        while (BigInteger.GreatestCommonDivisor(e, phi) != 1)
        {
            e += 2;
        }

        return e;
    }

    public static BigInteger ModInverse(BigInteger a, BigInteger m)
    {
        var (g, x, _) = ExtendedGcd(a, m);
        if (g != 1)
        {
            throw new InvalidOperationException("Обратный элемент не существует.");
        }

        return (x % m + m) % m;
    }

    private static (BigInteger gcd, BigInteger x, BigInteger y) ExtendedGcd(BigInteger a, BigInteger b)
    {
        if (b == 0)
        {
            return (a, 1, 0);
        }

        var (gcd, x1, y1) = ExtendedGcd(b, a % b);
        return (gcd, y1, x1 - (a / b) * y1);
    }

    public static int CalculateBlockSize(BigInteger n)
    {
        var size = 1;
        while (BigInteger.Pow(256, size) < n)
        {
            size++;
        }

        return Math.Max(1, size - 1);
    }

    private static IReadOnlyList<BigInteger> Encrypt(byte[] bytes, BigInteger e, BigInteger n, int blockSize)
    {
        var result = new List<BigInteger>();

        for (var i = 0; i < bytes.Length; i += blockSize)
        {
            var sliceLength = Math.Min(blockSize, bytes.Length - i);
            var block = new byte[sliceLength + 1];
            Array.Copy(bytes, i, block, 1, sliceLength);
            var number = new BigInteger(block.Reverse().ToArray());
            result.Add(BigInteger.ModPow(number, e, n));
        }

        return result;
    }

    private static byte[] Decrypt(IReadOnlyList<BigInteger> encrypted, BigInteger d, BigInteger n, int blockSize, int originalLength)
    {
        using var stream = new MemoryStream();
        foreach (var block in encrypted)
        {
            var plainNumber = BigInteger.ModPow(block, d, n);
            var temp = plainNumber.ToByteArray();
            Array.Reverse(temp);

            if (temp.Length > 0 && temp[0] == 0)
            {
                temp = temp[1..];
            }

            if (temp.Length < blockSize)
            {
                var padded = new byte[blockSize];
                Buffer.BlockCopy(temp, 0, padded, blockSize - temp.Length, temp.Length);
                temp = padded;
            }

            stream.Write(temp, 0, temp.Length);
        }

        var all = stream.ToArray();
        return all[..originalLength];
    }
}
