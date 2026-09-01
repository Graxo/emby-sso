using System;
using System.Threading.Tasks;
using Emby.Sso.Protocol;
using Xunit;

namespace Emby.Sso.Tests
{
    /// <summary>
    /// A REAL licence, signed by a key that has since been RETIRED, refused by
    /// the shipped build.
    ///
    /// This is the evidence that revocation is real. There is no revocation list
    /// and no callback - the plugin verifies offline and never contacts anything
    /// - so a key is revoked by not being in
    /// <see cref="LicencePublicKey.TrustedJwks"/>, and the only way to know that
    /// worked is to keep a licence it signed and check that it now fails.
    ///
    /// The token below came out of `licencetool sign` for real, on 2026-09-01,
    /// signed by key 173282303e3800b8 - an interim key whose private half lived
    /// on a development workspace the vendor does not control. It was dropped
    /// from the trusted set the moment the vendor's own key existed. This test
    /// says so and would fail loudly if it were ever quietly trusted again.
    ///
    /// WHAT THIS TEST NO LONGER PROVES, stated rather than hidden: it used to
    /// assert that a licence made by the real tool with the real key is ACCEPTED,
    /// which is the one property no generated-key test can give. That half
    /// lapsed with the rotation, because producing a new one needs the current
    /// private key and that key is deliberately nowhere near this repository. To
    /// restore it, sign a licence for the fictional server id below with the
    /// current key and add it back as an accepted case - `licencetool issue
    /// --server-id ... --days 3650` is enough.
    ///
    /// Neither token is a secret. Both are licences for a server id that does
    /// not exist, and a licence is public to whoever holds it in any case.
    /// </summary>
    public class RealLicenceTests
    {
        /// <summary>The server this licence names. Not a real Emby server.</summary>
        private const string ServerId = "c5bc6e91458540caa295c4efdda1a58a";

        /// <summary>
        /// Signed 2026-09-01 for one year, by the RETIRED key 173282303e3800b8.
        /// </summary>
        private const string RetiredKeyLicence =
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
        public async Task A_licence_signed_by_the_retired_key_is_refused()
        {
            // The whole point. This token was genuine, was accepted by an
            // earlier build, and names a server and a date that are both still
            // inside its own validity. It is refused for one reason: the key
            // that signed it is not trusted any more.
            var status = await LicenceCheck.EvaluateAsync(
                RetiredKeyLicence,
                LicencePublicKey.TrustedJwks,
                ServerId,
                Now);

            Assert.Equal(LicenceOutcome.BadSignature, status.Outcome);
        }

        [Fact]
        public async Task It_is_refused_even_on_the_server_it_names_and_inside_its_own_dates()
        {
            // Guards against a future reader concluding this fails for some
            // incidental reason - a wrong audience, an expiry - and "fixing" it
            // by trusting the key again. Neither of those is why.
            var beforeExpiry = await LicenceCheck.EvaluateAsync(
                RetiredKeyLicence,
                LicencePublicKey.TrustedJwks,
                ServerId,
                Now.AddMonths(6));

            Assert.Equal(LicenceOutcome.BadSignature, beforeExpiry.Outcome);
            Assert.NotEqual(LicenceOutcome.WrongServer, beforeExpiry.Outcome);
            Assert.NotEqual(LicenceOutcome.Expired, beforeExpiry.Outcome);
        }

        [Fact]
        public void This_build_trusts_exactly_one_key_and_it_is_the_vendors()
        {
            // A second entry appearing here is either a rotation in progress -
            // legitimate, and this assertion is then the thing to update
            // deliberately - or a retired key that crept back. Either way it
            // should be a decision somebody made, not a diff nobody read.
            Assert.Single(LicencePublicKey.TrustedJwks);

            var trusted = LicencePublicKey.TrustedJwks[0];

            Assert.Contains("\"kty\":\"RSA\"", trusted, StringComparison.Ordinal);
            Assert.DoesNotContain("\"d\"", trusted, StringComparison.Ordinal);

            // The two retired keys, by the start of their modulus. Neither may
            // return; a licence signed by either must stay refused.
            Assert.DoesNotContain("0sLbMum0TIALJnzGVTqcP1Bq02vp", trusted, StringComparison.Ordinal);
            Assert.DoesNotContain("4MRfQ1GfRQHBCePuyRQs_4SrzClG", trusted, StringComparison.Ordinal);
        }
    }
}
