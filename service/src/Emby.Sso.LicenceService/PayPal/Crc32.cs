using System;

namespace Emby.Sso.LicenceService.PayPal
{
    /// <summary>
    /// CRC-32 (IEEE 802.3, reflected, polynomial 0xEDB88320) - the same one zip
    /// and gzip use.
    ///
    /// PayPal's signed message contains the CRC-32 of the raw request body
    /// rather than the body itself, so this has to produce exactly the number
    /// their signer produced or nothing verifies. It is here rather than taken
    /// from a package because it is twenty lines of table lookup and this
    /// service already holds a signing key; a dependency that runs code on that
    /// box has to earn its place.
    ///
    /// It is NOT a security function and nothing here treats it as one. Its
    /// integrity comes entirely from being inside the RSA-signed message: an
    /// attacker who edits the body must produce a body with the SAME CRC and
    /// then still cannot sign the message.
    /// </summary>
    internal static class Crc32
    {
        private static readonly uint[] Table = BuildTable();

        public static uint Compute(ReadOnlySpan<byte> data)
        {
            var crc = 0xFFFFFFFFu;

            foreach (var b in data)
            {
                crc = Table[(crc ^ b) & 0xFF] ^ (crc >> 8);
            }

            return crc ^ 0xFFFFFFFFu;
        }

        private static uint[] BuildTable()
        {
            const uint Polynomial = 0xEDB88320u;

            var table = new uint[256];

            for (var i = 0u; i < 256u; i++)
            {
                var entry = i;

                for (var bit = 0; bit < 8; bit++)
                {
                    entry = (entry & 1) != 0 ? (entry >> 1) ^ Polynomial : entry >> 1;
                }

                table[i] = entry;
            }

            return table;
        }
    }
}
