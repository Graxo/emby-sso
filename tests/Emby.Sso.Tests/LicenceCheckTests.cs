using System;
using System.Threading.Tasks;
using Emby.Sso.Protocol;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Emby.Sso.Tests
{
    /// <summary>
    /// The licence decision. This is a JWT validated against a public key that
    /// ships inside the assembly, so the two classic JWT bypasses apply
    /// directly and are tested here by name: <c>alg: none</c>, and an
    /// HMAC-signed token presented where an asymmetric key is expected.
    ///
    /// Following the precedent of <c>OidcClientSignatureTests</c>, each test
    /// below that names a guard was confirmed to FAIL when that guard is
    /// removed from <c>LicenceCheck</c>, not merely to pass against the correct
    /// code. The mutations checked were: <c>RequireSignedTokens = false</c>,
    /// deleting the <c>ValidAlgorithms</c> pin, replacing it with an empty
    /// array, <c>ValidateAudience = false</c>, returning <c>true</c> from the
    /// lifetime delegate when <c>exp</c> is absent, dropping the future-<c>iat</c>
    /// refusal, and dropping the private-material check on the embedded key.
    ///
    /// A licence check that a crafted token can walk through is worse than no
    /// licence check, because it looks like protection.
    /// </summary>
    public class LicenceCheckTests : IDisposable
    {
        private readonly LicenceFactory _factory = new LicenceFactory();
        private readonly DateTimeOffset _now = DateTimeOffset.UtcNow;

        public void Dispose() => _factory.Dispose();

        private Task<LicenceStatus> Evaluate(string licence, string serverId = LicenceFactory.ServerId, string publicKey = null)
        {
            return LicenceCheck.EvaluateAsync(licence, publicKey ?? _factory.PublicKeyJwk, serverId, _now);
        }

        [Fact]
        public async Task A_valid_licence_is_accepted()
        {
            var status = await Evaluate(_factory.Issue(expires: DateTime.UtcNow.AddDays(365)));

            Assert.Equal(LicenceOutcome.Valid, status.Outcome);
            Assert.True(LicenceCheck.Permits(status.Outcome));
            Assert.Equal("Test Operator", status.Licensee);
            Assert.NotNull(status.ExpiresAt);
        }

        [Fact]
        public async Task A_licence_close_to_expiry_still_admits_but_says_so()
        {
            // The warning is the whole reason existing sessions are kept alive
            // through a licensing failure: it is what gives the operator time to
            // act. It must not also be a refusal.
            var status = await Evaluate(_factory.Issue(expires: DateTime.UtcNow.AddDays(3)));

            Assert.Equal(LicenceOutcome.ExpiringSoon, status.Outcome);
            Assert.True(LicenceCheck.Permits(status.Outcome));
        }

        [Fact]
        public async Task An_absent_licence_is_missing_not_valid()
        {
            foreach (var empty in new[] { null, string.Empty, "   " })
            {
                var status = await Evaluate(empty);

                Assert.Equal(LicenceOutcome.Missing, status.Outcome);
                Assert.False(LicenceCheck.Permits(status.Outcome));
            }
        }

        [Fact]
        public async Task Rubbish_is_malformed()
        {
            var status = await Evaluate("not-a-jwt-at-all");

            Assert.False(LicenceCheck.Permits(status.Outcome));
            Assert.Equal(LicenceOutcome.Malformed, status.Outcome);
        }

        [Fact]
        public async Task A_licence_signed_by_the_wrong_key_is_refused()
        {
            // Correct in every other respect - right issuer, right server, in
            // date. Only the signature is somebody else's.
            var status = await Evaluate(_factory.Issue(signedByAStranger: true));

            Assert.Equal(LicenceOutcome.BadSignature, status.Outcome);
            Assert.False(LicenceCheck.Permits(status.Outcome));
        }

        [Fact]
        public async Task An_unsigned_licence_is_refused()
        {
            // "alg": "none" with an empty signature. Everything else about the
            // token is correct, so the only thing that can refuse it is
            // RequireSignedTokens. Kills the RequireSignedTokens = false mutant.
            var licence = LicenceFactory.Unsigned();

            Assert.Equal(string.Empty, licence.Split('.')[2]);

            var status = await Evaluate(licence);

            Assert.False(LicenceCheck.Permits(status.Outcome));
        }

        [Fact]
        public async Task An_hmac_signed_licence_keyed_on_the_public_key_is_refused()
        {
            // The classic algorithm-confusion attack. The "secret" is the RSA
            // modulus that ships inside the plugin, so every holder of the DLL
            // has it; if the validator could be talked into treating the
            // embedded key as an HMAC key, anybody could mint a licence.
            //
            // Honest about what this one measures: it stays green with the
            // ValidAlgorithms pin deleted, because the embedded key is a JWK of
            // kty RSA and IdentityModel will not build a symmetric signature
            // provider from one. TWO independent things refuse it, and this test
            // pins the outcome rather than either mechanism. The test above is
            // the one that dies when the pin dies.
            var status = await Evaluate(_factory.HmacSignedWithThePublicKey());

            Assert.False(LicenceCheck.Permits(status.Outcome));
            Assert.NotEqual("Forged", status.Licensee);
        }

        [Fact]
        public async Task A_licence_signed_with_an_algorithm_this_build_does_not_accept_is_refused()
        {
            // Signed RS512 with the REAL licence key, so the signature verifies
            // and the only thing that can refuse it is the ValidAlgorithms pin.
            // Kills both the "delete the pin" mutant and the "make it an empty
            // array" mutant - an empty ValidAlgorithms is read by the token
            // handler as no restriction at all.
            var status = await Evaluate(_factory.Issue(algorithm: SecurityAlgorithms.RsaSha512));

            Assert.Equal(LicenceOutcome.BadSignature, status.Outcome);
            Assert.False(LicenceCheck.Permits(status.Outcome));
        }

        [Fact]
        public async Task A_licence_for_another_server_is_refused()
        {
            var status = await Evaluate(_factory.Issue(serverId: "0000000000000000000000000000ffff"));

            Assert.Equal(LicenceOutcome.WrongServer, status.Outcome);
            Assert.False(LicenceCheck.Permits(status.Outcome));
        }

        [Fact]
        public async Task A_licence_checked_against_a_server_that_reports_no_id_is_refused()
        {
            // A binding that cannot be checked has not been checked. Refusing
            // is what stops a missing SystemId from silently turning the server
            // binding off for everybody.
            foreach (var missing in new[] { null, string.Empty, "  " })
            {
                var status = await Evaluate(_factory.Issue(), serverId: missing);

                Assert.Equal(LicenceOutcome.WrongServer, status.Outcome);
                Assert.False(LicenceCheck.Permits(status.Outcome));
            }
        }

        [Fact]
        public async Task An_expired_licence_is_refused()
        {
            var status = await Evaluate(_factory.Issue(
                issuedAt: DateTime.UtcNow.AddDays(-400),
                expires: DateTime.UtcNow.AddDays(-1)));

            Assert.Equal(LicenceOutcome.Expired, status.Outcome);
            Assert.False(LicenceCheck.Permits(status.Outcome));
            Assert.Null(status.Licensee);
        }

        [Fact]
        public async Task A_licence_with_no_expiry_at_all_is_refused()
        {
            // A perpetual licence is not a licence. The library's own
            // RequireExpirationTime does NOT cover this - supplying a
            // LifetimeValidator short-circuits it - so the refusal has to be in
            // the delegate, and this is the test that says so.
            var status = await Evaluate(_factory.Issue(includeExpiry: false));

            Assert.Equal(LicenceOutcome.Expired, status.Outcome);
            Assert.False(LicenceCheck.Permits(status.Outcome));
        }

        [Fact]
        public async Task A_licence_dated_in_the_future_is_refused_rather_than_held()
        {
            // nbf is pinned to now on purpose, so that the library's own
            // not-before check cannot be what refuses this and the explicit
            // future-`iat` refusal is the only thing left holding the line.
            // `iat` is not part of any lifetime validation IdentityModel does.
            var status = await Evaluate(_factory.Issue(
                issuedAt: DateTime.UtcNow.AddDays(30),
                notBefore: DateTime.UtcNow,
                expires: DateTime.UtcNow.AddDays(400)));

            Assert.Equal(LicenceOutcome.NotYetValid, status.Outcome);
            Assert.False(LicenceCheck.Permits(status.Outcome));
        }

        [Fact]
        public async Task A_licence_whose_nbf_is_in_the_future_is_refused()
        {
            var status = await Evaluate(_factory.Issue(notBefore: DateTime.UtcNow.AddDays(30)));

            Assert.Equal(LicenceOutcome.NotYetValid, status.Outcome);
            Assert.False(LicenceCheck.Permits(status.Outcome));
        }

        [Fact]
        public async Task A_licence_with_no_issued_at_claim_is_refused()
        {
            var status = await Evaluate(_factory.Issue(includeIssuedAt: false));

            Assert.Equal(LicenceOutcome.Malformed, status.Outcome);
            Assert.False(LicenceCheck.Permits(status.Outcome));
        }

        [Fact]
        public async Task A_licence_edited_after_signing_is_refused()
        {
            // The signature is intact and genuinely ours; the payload is not the
            // one that was signed. This is what an operator moving a licence to
            // a second server would try first.
            var tampered = LicenceFactory.Tamper(_factory.Issue(), "aud", "0000000000000000000000000000ffff");

            var status = await Evaluate(tampered, serverId: "0000000000000000000000000000ffff");

            Assert.Equal(LicenceOutcome.BadSignature, status.Outcome);
            Assert.False(LicenceCheck.Permits(status.Outcome));
        }

        [Fact]
        public async Task A_licence_from_a_different_issuer_is_refused()
        {
            var status = await Evaluate(_factory.Issue(issuer: "urn:someone-elses:licence"));

            Assert.False(LicenceCheck.Permits(status.Outcome));
        }

        [Fact]
        public async Task A_build_with_no_embedded_public_key_licenses_nobody()
        {
            // The state a fresh checkout is in. It must refuse rather than
            // accept, and it must say why - LicencePublicKey.Jwk is empty until
            // a release build fills it in.
            var status = await Evaluate(_factory.Issue(), publicKey: "");

            Assert.Equal(LicenceOutcome.BadSignature, status.Outcome);
            Assert.False(LicenceCheck.Permits(status.Outcome));
            Assert.Contains("no licence public key", status.Detail);
        }

        [Fact]
        public async Task A_build_that_embedded_the_PRIVATE_key_licenses_nobody()
        {
            // The one release mistake that would give the whole scheme away:
            // pasting the signing key's private half into the public constant,
            // shipping it in every copy, and letting anyone mint licences.
            // Refused loudly rather than working perfectly.
            var status = await Evaluate(_factory.Issue(), publicKey: _factory.PrivateKeyJwk);

            Assert.Equal(LicenceOutcome.BadSignature, status.Outcome);
            Assert.False(LicenceCheck.Permits(status.Outcome));
            Assert.Contains("PRIVATE", status.Detail);
        }

        [Fact]
        public void Only_the_two_admitting_outcomes_permit()
        {
            // The whitelist, over every member the enum has. A future member
            // added without updating Permits must not license anybody, and the
            // default-initialised value (Missing = 0) must not either.
            foreach (LicenceOutcome outcome in Enum.GetValues(typeof(LicenceOutcome)))
            {
                var expected = outcome == LicenceOutcome.Valid || outcome == LicenceOutcome.ExpiringSoon;

                Assert.Equal(expected, LicenceCheck.Permits(outcome));
            }

            Assert.Equal(LicenceOutcome.Missing, default(LicenceOutcome));
            Assert.False(LicenceCheck.Permits(default(LicenceOutcome)));
        }

        [Fact]
        public async Task The_embedded_public_key_this_build_ships_is_either_empty_or_a_usable_rsa_public_key()
        {
            // Guards the release step described in LicencePublicKey: paste the
            // tool's PUBLIC jwk in, rebuild. A constant that is neither empty
            // nor a usable RSA public key is a build that refuses every sign-in
            // for a reason nobody would look for.
            if (string.IsNullOrWhiteSpace(LicencePublicKey.Jwk))
            {
                return;
            }

            var status = await LicenceCheck.EvaluateAsync(
                _factory.Issue(),
                LicencePublicKey.Jwk,
                LicenceFactory.ServerId,
                _now);

            // Signed by the test's key, not the vendor's, so a bad signature is
            // the RIGHT answer here. What must NOT happen is the key itself
            // being rejected as unusable.
            Assert.Equal(LicenceOutcome.BadSignature, status.Outcome);
            Assert.DoesNotContain("embedded licence key", status.Detail);
            Assert.DoesNotContain("no licence public key", status.Detail);
        }
    }
}
