using System;
using System.Threading.Tasks;
using Emby.Sso.Protocol;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Emby.Sso.Tests
{
    /// <summary>
    /// The renewed licence the daily status check can hand back. It is only
    /// data from the network, so it is accepted exactly as a licence is at
    /// activation - trusted keys, issuer, audience = this server - and then only
    /// if it runs LONGER than the licence already held. Everything else leaves
    /// the stored licence alone.
    /// </summary>
    public class LicenceRenewalTests
    {
        private const string ServerId = LicenceFactory.ServerId;
        private const string OtherServer = "0b3d0f8fd4d9412e9c4e5ba0d09a3f77";
        private const string Fingerprint = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

        private readonly LicenceFactory _vendor = new LicenceFactory();
        private readonly DateTimeOffset _now = new DateTimeOffset(2026, 9, 2, 12, 0, 0, TimeSpan.Zero);

        private DateTime Now => _now.UtcDateTime;

        [Fact]
        public async Task A_valid_licence_that_runs_longer_is_accepted()
        {
            var held = _vendor.Issue(issuedAt: Now, expires: Now.AddDays(10));
            var renewed = _vendor.Issue(issuedAt: Now, expires: Now.AddDays(375));

            var result = await Evaluate(renewed, held);

            Assert.True(result.Accepted);
            Assert.Equal(new DateTimeOffset(Now.AddDays(375)).ToUnixTimeSeconds(), result.ExpiresAt.Value.ToUnixTimeSeconds());
        }

        [Fact]
        public async Task A_licence_that_runs_less_long_is_ignored()
        {
            var held = _vendor.Issue(issuedAt: Now, expires: Now.AddDays(100));
            var renewed = _vendor.Issue(issuedAt: Now, expires: Now.AddDays(50));

            Assert.False((await Evaluate(renewed, held)).Accepted);
        }

        [Fact]
        public async Task A_licence_that_runs_exactly_as_long_is_ignored()
        {
            var held = _vendor.Issue(issuedAt: Now, expires: Now.AddDays(100));
            var renewed = _vendor.Issue(issuedAt: Now, expires: Now.AddDays(100));

            Assert.False((await Evaluate(renewed, held)).Accepted);
        }

        [Fact]
        public async Task A_licence_for_another_server_is_ignored()
        {
            var held = _vendor.Issue(issuedAt: Now, expires: Now.AddDays(10));
            var renewed = _vendor.Issue(serverId: OtherServer, issuedAt: Now, expires: Now.AddDays(375));

            Assert.False((await Evaluate(renewed, held)).Accepted);
        }

        [Fact]
        public async Task A_licence_signed_by_a_stranger_is_ignored()
        {
            var held = _vendor.Issue(issuedAt: Now, expires: Now.AddDays(10));
            var renewed = _vendor.Issue(issuedAt: Now, expires: Now.AddDays(375), signedByAStranger: true);

            Assert.False((await Evaluate(renewed, held)).Accepted);
        }

        [Fact]
        public async Task An_already_expired_licence_is_ignored()
        {
            var held = _vendor.Issue(issuedAt: Now.AddDays(-400), expires: Now.AddDays(-35));
            var renewed = _vendor.Issue(issuedAt: Now.AddDays(-400), expires: Now.AddDays(-30));

            Assert.False((await Evaluate(renewed, held)).Accepted);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("not-a-token")]
        public async Task Nothing_that_is_not_a_licence_is_accepted(string renewed)
        {
            var held = _vendor.Issue(issuedAt: Now, expires: Now.AddDays(10));

            Assert.False((await Evaluate(renewed, held)).Accepted);
        }

        [Fact]
        public async Task A_renewal_replaces_a_held_licence_that_has_itself_expired()
        {
            // The held licence no longer validates - that is when a renewal is
            // most welcome - so its own exp is read without trusting it.
            var held = _vendor.Issue(issuedAt: Now.AddDays(-400), expires: Now.AddDays(-35));
            var renewed = _vendor.Issue(issuedAt: Now, expires: Now.AddDays(365));

            Assert.True((await Evaluate(renewed, held)).Accepted);
        }

        [Fact]
        public async Task The_status_body_hands_the_licence_over_beside_a_valid_status()
        {
            var body = "{\"status\":\"" + Status("valid") + "\",\"licence\":\"the.renewed.licence\"}";

            var answer = await Read(body);

            Assert.Equal(LicenceStatusOutcome.Valid, answer.Outcome);
            Assert.Equal("the.renewed.licence", answer.RenewedLicence);
        }

        [Fact]
        public async Task A_status_body_without_a_licence_carries_none()
        {
            var answer = await Read("{\"status\":\"" + Status("valid") + "\"}");

            Assert.Equal(LicenceStatusOutcome.Valid, answer.Outcome);
            Assert.Null(answer.RenewedLicence);
        }

        [Theory]
        [InlineData("revoked")]
        [InlineData("unknown")]
        public async Task A_licence_beside_any_other_status_is_not_carried(string status)
        {
            var answer = await Read("{\"status\":\"" + Status(status) + "\",\"licence\":\"x.y.z\"}");

            Assert.Null(answer.RenewedLicence);
        }

        [Fact]
        public async Task A_licence_beside_an_unverifiable_status_is_not_carried()
        {
            var answer = await Read("{\"status\":\"garbage\",\"licence\":\"x.y.z\"}");

            Assert.Equal(LicenceStatusOutcome.NoAnswer, answer.Outcome);
            Assert.Null(answer.RenewedLicence);
        }

        [Fact]
        public async Task A_licence_that_is_not_a_string_is_not_carried()
        {
            var answer = await Read("{\"status\":\"" + Status("valid") + "\",\"licence\":42}");

            Assert.Equal(LicenceStatusOutcome.Valid, answer.Outcome);
            Assert.Null(answer.RenewedLicence);
        }

        private Task<LicenceRenewal> Evaluate(string renewed, string held)
        {
            return LicenceRenewal.EvaluateAsync(renewed, held, new[] { _vendor.PublicKeyJwk }, ServerId, _now);
        }

        private Task<LicenceStatusAnswer> Read(string body)
        {
            return LicenceStatusClient.ReadAnswerAsync(body, new[] { _vendor.PublicKeyJwk }, ServerId, Fingerprint, _now);
        }

        private string Status(string status)
        {
            var payload = "{"
                + "\"iss\":\"" + LicenceStatusCheck.Issuer + "\","
                + "\"aud\":\"" + ServerId + "\","
                + "\"sub\":\"" + Fingerprint + "\","
                + "\"" + LicenceStatusCheck.StatusClaim + "\":\"" + status + "\","
                + "\"iat\":" + EpochTime.GetIntDate(Now) + ","
                + "\"nbf\":" + EpochTime.GetIntDate(Now) + ","
                + "\"exp\":" + EpochTime.GetIntDate(Now.AddDays(2))
                + "}";

            return new JsonWebTokenHandler().CreateToken(
                payload,
                new SigningCredentials(_vendor.SigningKey, SecurityAlgorithms.RsaSha256));
        }
    }
}
