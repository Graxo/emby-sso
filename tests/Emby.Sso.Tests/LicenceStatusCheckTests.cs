using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Emby.Sso.Protocol;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Emby.Sso.Tests
{
    /// <summary>
    /// The daily licence check, and the one property that matters more than all
    /// the others: IT FAILS OPEN.
    ///
    /// This runs unattended, over the network, on somebody else's server, and
    /// the only thing it can do is take working single sign-on away. So every
    /// test here that is not about a correctly signed revocation asserts that
    /// NOTHING CHANGES - because the vendor's server being unreachable, or a
    /// hostile network dropping packets, must never become a customer's outage.
    ///
    /// Exactly one thing stops sign-ins: a current, correctly signed token,
    /// naming this server and this licence, that says revoked.
    /// </summary>
    public class LicenceStatusCheckTests
    {
        private const string ServerId = "c5bc6e91458540caa295c4efdda1a58a";
        private const string OtherServer = "0b3d0f8fd4d9412e9c4e5ba0d09a3f77";
        private const string Fingerprint = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
        private const string OtherFingerprint = "sha256:2222222222222222222222222222222222222222222222222222222222222222";

        private readonly LicenceFactory _vendor = new LicenceFactory();
        private readonly DateTimeOffset _now = new DateTimeOffset(2026, 9, 2, 12, 0, 0, TimeSpan.Zero);

        [Fact]
        public async Task A_signed_revocation_for_this_server_stops_sign_ins()
        {
            var outcome = await Read(Token("revoked"));

            Assert.Equal(LicenceStatusOutcome.Revoked, outcome);
            Assert.True(LicenceStatusCheck.StopsSignIns(outcome));
        }

        [Fact]
        public async Task A_signed_valid_answer_changes_nothing()
        {
            var outcome = await Read(Token("valid"));

            Assert.Equal(LicenceStatusOutcome.Valid, outcome);
            Assert.False(LicenceStatusCheck.StopsSignIns(outcome));
        }

        [Fact]
        public async Task An_unknown_licence_is_treated_as_valid()
        {
            // A restored backup or a rebuilt vendor store looks exactly like
            // this, and a forged licence would have failed its signature check
            // long before reaching here.
            var outcome = await Read(Token("unknown"));

            Assert.Equal(LicenceStatusOutcome.Unknown, outcome);
            Assert.False(LicenceStatusCheck.StopsSignIns(outcome));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData("not-a-token")]
        [InlineData("a.b.c")]
        public async Task Nothing_that_is_not_a_token_can_change_anything(string token)
        {
            Assert.Equal(LicenceStatusOutcome.NoAnswer, await Read(token));
        }

        [Fact]
        public async Task A_revocation_signed_by_a_stranger_is_ignored()
        {
            // The attack this defends against: anyone who can answer for the
            // vendor's address - a hijacked DNS entry, a proxy, a hostile
            // network - switching off somebody's plugin.
            var stranger = new LicenceFactory();

            var token = Token("revoked", signer: stranger);

            Assert.Equal(LicenceStatusOutcome.NoAnswer, await Read(token));
        }

        [Fact]
        public async Task A_revocation_for_a_different_server_is_ignored()
        {
            Assert.Equal(LicenceStatusOutcome.NoAnswer, await Read(Token("revoked", audience: OtherServer)));
        }

        [Fact]
        public async Task A_revocation_about_a_different_licence_is_ignored()
        {
            // Without this, one signed answer about any licence the vendor ever
            // issued would apply to every licence.
            Assert.Equal(LicenceStatusOutcome.NoAnswer, await Read(Token("revoked", subject: OtherFingerprint)));
        }

        [Fact]
        public async Task An_expired_answer_is_ignored()
        {
            // So an answer captured before a revocation cannot be replayed after
            // one - and, in the other direction, so a stale "valid" cannot be
            // held open indefinitely.
            var token = Token("revoked", issuedAt: _now.AddDays(-30));

            Assert.Equal(LicenceStatusOutcome.NoAnswer, await Read(token));
        }

        [Fact]
        public async Task An_answer_from_the_future_is_ignored()
        {
            Assert.Equal(LicenceStatusOutcome.NoAnswer, await Read(Token("revoked", issuedAt: _now.AddDays(5))));
        }

        [Fact]
        public async Task A_status_word_this_build_does_not_know_is_ignored()
        {
            // The refusing default, in both directions: a future status must not
            // disable anybody, and must not silently read as valid either.
            Assert.Equal(LicenceStatusOutcome.NoAnswer, await Read(Token("disabled-forever")));
        }

        [Fact]
        public async Task A_licence_presented_as_a_status_is_ignored()
        {
            // Distinct issuers exist so that one kind of token can never be read
            // as the other. A licence says nothing about revocation.
            var licence = _vendor.Issue();

            Assert.Equal(LicenceStatusOutcome.NoAnswer, await Read(licence));
        }

        [Fact]
        public async Task With_no_trusted_keys_nothing_can_change_anything()
        {
            var outcome = await LicenceStatusCheck.ReadAsync(
                Token("revoked"),
                new string[0],
                ServerId,
                Fingerprint,
                _now);

            Assert.Equal(LicenceStatusOutcome.NoAnswer, outcome);
        }

        private Task<LicenceStatusOutcome> Read(string token)
        {
            return LicenceStatusCheck.ReadAsync(
                token,
                new[] { _vendor.PublicKeyJwk },
                ServerId,
                Fingerprint,
                _now);
        }

        private string Token(
            string status,
            LicenceFactory signer = null,
            string audience = null,
            string subject = null,
            DateTimeOffset? issuedAt = null)
        {
            var at = issuedAt ?? _now;

            var payload = "{"
                + "\"iss\":\"" + LicenceStatusCheck.Issuer + "\","
                + "\"aud\":\"" + (audience ?? ServerId) + "\","
                + "\"sub\":\"" + (subject ?? Fingerprint) + "\","
                + "\"" + LicenceStatusCheck.StatusClaim + "\":\"" + status + "\","
                + "\"iat\":" + EpochTime.GetIntDate(at.UtcDateTime) + ","
                + "\"nbf\":" + EpochTime.GetIntDate(at.UtcDateTime) + ","
                + "\"exp\":" + EpochTime.GetIntDate(at.AddDays(2).UtcDateTime)
                + "}";

            return new JsonWebTokenHandler().CreateToken(
                payload,
                new SigningCredentials((signer ?? _vendor).SigningKey, SecurityAlgorithms.RsaSha256));
        }
    }
}
