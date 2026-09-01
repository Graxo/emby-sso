using System;
using System.Threading.Tasks;
using Emby.Sso.Protocol;
using Xunit;

namespace Emby.Sso.Tests
{
    /// <summary>
    /// One real licence, signed by the real key, checked by the shipped build.
    ///
    /// Every other test in this suite signs with a key the test generated, which
    /// proves the algorithm and proves nothing about the key this build actually
    /// trusts. This one closes that gap: the token below came out of
    /// `licencetool sign` on the vendor's signing machine, with the private half
    /// of the key in <see cref="LicencePublicKey.TrustedJwks"/>. If the two ever
    /// stop matching - a key pasted in wrong, a canonicalisation changed, an
    /// entry dropped by accident - every customer is refused, and this fails
    /// first.
    ///
    /// WHEN YOU ROTATE A KEY, THIS TEST IS PART OF IT. Adding a key leaves this
    /// passing, because the old key is still trusted. REMOVING the key that
    /// signed this token makes it fail, correctly: replace the token with one
    /// signed by a current key, and check in the new one alongside the change.
    /// A green suite after a revocation that this did not notice would mean the
    /// revocation had not happened.
    ///
    /// It is not a secret. It is a licence for a server id that does not exist,
    /// and a licence is public to whoever holds it in any case.
    /// </summary>
    public class RealLicenceTests
    {
        /// <summary>The server this licence names. Not a real Emby server.</summary>
        private const string ServerId = "c5bc6e91458540caa295c4efdda1a58a";

        /// <summary>
        /// Signed 2026-09-01 for one year, by key 173282303e3800b8.
        /// </summary>
        private const string Licence =
            "eyJhbGciOiJSUzI1NiIsImtpZCI6IjE3MzI4MjMwM2UzODAwYjgiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJ1cm46ZW1ieS1zc"
            + "286bGljZW5jZSIsInN1YiI6ImNvZGU6YWIxMmNkMzRlZjU2IiwiYXVkIjoiYzViYzZlOTE0NTg1NDBjYWEyOTVjNGVmZGRhM"
            + "WE1OGEiLCJpYXQiOjE3ODgyNjQwMDAsIm5iZiI6MTc4ODI2NDAwMCwiZXhwIjoxODE5ODAwMDAwfQ.3CL_9r4cMuXaIZKKNa"
            + "rLgO9Gn1cNettYCCfm3n3ZqhfRyuHEJ0ZZmFMW6RbZ5oQu9VIkdBn_54JVIJliIr4pTyAauHttBV0ibRZq2KLdRLv81jxedz"
            + "Ux_qgezanN1NOhs3KJBOzG8vW-QITF41xECHYyRRmJWs_qYCc-MZgpvbR1AE1FgSDOed0BdbiXH8gD3I5vKtSL602J4maGuT"
            + "FusHfWrvBg8zTrPKS5aWLmsteluNUwhWxzxgt6Au8zlJippT_pKgakeFFD9SdOimZm9nXHo7O68OHNnZG7ytoxJEnLcmrXku"
            + "esOFvO2MQRjmiwKbRrBo50ARQvhY4CHDOOlXDIy9U_KzGcyVhbXAqUITbf3wZhENxIvT23t3rSALUC3hQeNxKOdrbqhloPOC"
            + "BmvQSVhy-b1iaTIxcRAdk_DowjLGbAZta0kF_z_UNdTGm4aly6tx3b8n57298B8qs1mQnFgs_46anyJikOc9LEwqdQahDxZR"
            + "O5hA8cSj-uQXeu";

        /// <summary>
        /// Fixed, not DateTimeOffset.UtcNow. A test that reads the wall clock
        /// would pass for a year and then start failing on a date nobody chose,
        /// with a message about an expired licence rather than about the key.
        /// </summary>
        private static readonly DateTimeOffset Now = new DateTimeOffset(2026, 9, 15, 12, 0, 0, TimeSpan.Zero);

        [Fact]
        public async Task The_shipped_build_accepts_a_licence_signed_by_the_real_key()
        {
            var status = await LicenceCheck.EvaluateAsync(Licence, LicencePublicKey.TrustedJwks, ServerId, Now);

            Assert.Equal(LicenceOutcome.Valid, status.Outcome);
            Assert.Equal("code:ab12cd34ef56", status.Licensee);
        }

        [Fact]
        public async Task It_is_refused_on_a_different_server()
        {
            var status = await LicenceCheck.EvaluateAsync(
                Licence,
                LicencePublicKey.TrustedJwks,
                "0b3d0f8fd4d9412e9c4e5ba0d09a3f77",
                Now);

            Assert.Equal(LicenceOutcome.WrongServer, status.Outcome);
        }

        [Fact]
        public async Task It_is_refused_once_it_has_expired()
        {
            var status = await LicenceCheck.EvaluateAsync(
                Licence,
                LicencePublicKey.TrustedJwks,
                ServerId,
                Now.AddYears(2));

            Assert.Equal(LicenceOutcome.Expired, status.Outcome);
        }

        [Fact]
        public async Task A_single_altered_character_is_refused()
        {
            // The signature is what admits it, and nothing else. Flipping one
            // character of the payload must not be survivable.
            var tampered = Licence.Substring(0, 40)
                + (Licence[40] == 'A' ? 'B' : 'A')
                + Licence.Substring(41);

            var status = await LicenceCheck.EvaluateAsync(tampered, LicencePublicKey.TrustedJwks, ServerId, Now);

            Assert.NotEqual(LicenceOutcome.Valid, status.Outcome);
            Assert.NotEqual(LicenceOutcome.ExpiringSoon, status.Outcome);
        }
    }
}
