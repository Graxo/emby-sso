using System.Text;

namespace Emby.Sso.Protocol
{
    /// <summary>
    /// Comparison whose duration does not depend on where two values first differ.
    /// netstandard2.0 has no CryptographicOperations.FixedTimeEquals.
    /// </summary>
    public static class FixedTime
    {
        public static bool Equals(string a, string b)
        {
            if (a == null || b == null)
            {
                return false;
            }

            var left = Encoding.UTF8.GetBytes(a);
            var right = Encoding.UTF8.GetBytes(b);

            var difference = left.Length ^ right.Length;
            var length = left.Length < right.Length ? left.Length : right.Length;

            for (var i = 0; i < length; i++)
            {
                difference |= left[i] ^ right[i];
            }

            return difference == 0;
        }
    }
}
