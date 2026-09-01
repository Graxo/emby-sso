using System;
using System.Security.Cryptography;

namespace Emby.Sso.LicenceService.Storage
{
    /// <summary>
    /// The opaque name a licence-to-be-signed is matched on, from the file this
    /// service hands out to the file that comes back.
    ///
    /// UNGUESSABLE, AND SAYING NOTHING. It is written into a file that leaves
    /// this machine - a browser download, a USB stick, possibly an email - and
    /// then comes back through a form. So it must not encode the customer, the
    /// redemption code, the server id or the row number: an id that leaked any
    /// of those would put them in every copy of that file forever. And it must
    /// not be guessable, because the upload path looks a request up by it; a
    /// sequential id would let anyone who reached the admin page overwrite a
    /// specific customer's request by counting.
    ///
    /// 128 bits from the cryptographic generator, hex. Not a GUID: Guid.NewGuid
    /// is version 4 and random in practice, but nothing in its contract says so,
    /// and this is not the place to rely on an implementation detail.
    /// </summary>
    public static class SigningRequestId
    {
        public const int Bytes = 16;

        public static string New()
        {
            var bytes = RandomNumberGenerator.GetBytes(Bytes);

            return Convert.ToHexString(bytes).ToLowerInvariant();
        }

        /// <summary>
        /// Whether a string could be one of ours. Checked before a lookup so
        /// that a hand-edited file fails with a sentence about the file rather
        /// than with "no such request", which reads as "the service lost it".
        /// </summary>
        public static bool IsWellFormed(string value)
        {
            if (value == null || value.Length != Bytes * 2)
            {
                return false;
            }

            foreach (var c in value)
            {
                var ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');

                if (!ok)
                {
                    return false;
                }
            }

            return true;
        }
    }
}
