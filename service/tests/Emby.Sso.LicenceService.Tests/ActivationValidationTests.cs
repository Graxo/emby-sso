using System;
using Emby.Sso.LicenceService.Activation;
using Emby.Sso.Licensing;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// contract.md: malformed_request is "missing/!well-formed code or serverId".
    /// These draw that line, and check the other side of it - that a well-formed
    /// code which happens to be unknown is invalid_code, not malformed_request,
    /// because the plugin says something different to the customer for each.
    /// </summary>
    public class ActivationValidationTests : IDisposable
    {
        private readonly TestService _service = new TestService();

        public void Dispose()
        {
            _service.Dispose();
        }

        [Fact]
        public void A_null_request_is_malformed_rather_than_an_exception()
        {
            Assert.Equal(ActivationError.MalformedRequest, _service.Activations.Activate(null, "10.0.0.1").Error);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public void A_missing_code_is_malformed(string code)
        {
            var reply = Activate(code, "c5bc6e91458540caa295c4efdda1a58a");

            Assert.Equal(ActivationError.MalformedRequest, reply.Error);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public void A_missing_server_id_is_malformed(string serverId)
        {
            var reply = Activate(RedemptionCode.Format(RedemptionCode.Generate()), serverId);

            Assert.Equal(ActivationError.MalformedRequest, reply.Error);
        }

        [Theory]
        [InlineData("not a code")]
        [InlineData("ABC-DEF")]
        [InlineData("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")]
        public void A_code_that_is_not_the_right_shape_is_malformed_not_invalid(string code)
        {
            var reply = Activate(code, "c5bc6e91458540caa295c4efdda1a58a");

            Assert.Equal(ActivationError.MalformedRequest, reply.Error);
        }

        [Fact]
        public void A_well_formed_code_that_does_not_exist_is_invalid_code()
        {
            var reply = Activate(RedemptionCode.Format(RedemptionCode.Generate()), "c5bc6e91458540caa295c4efdda1a58a");

            Assert.Equal(ActivationError.InvalidCode, reply.Error);
        }

        [Theory]
        [InlineData("server with spaces")]
        [InlineData("<script>alert(1)</script>")]
        [InlineData("'; DROP TABLE codes; --")]
        [InlineData("../../etc/passwd")]
        public void A_server_id_that_is_not_an_identifier_is_malformed(string serverId)
        {
            var reply = Activate(_service.GiveOutACode(), serverId);

            Assert.Equal(ActivationError.MalformedRequest, reply.Error);
        }

        [Fact]
        public void An_absurdly_long_server_id_is_malformed()
        {
            var reply = Activate(_service.GiveOutACode(), new string('a', 65));

            Assert.Equal(ActivationError.MalformedRequest, reply.Error);
        }

        [Fact]
        public void An_absurdly_long_code_is_malformed_and_is_never_hashed()
        {
            var reply = Activate(new string('2', 100000), "c5bc6e91458540caa295c4efdda1a58a");

            Assert.Equal(ActivationError.MalformedRequest, reply.Error);
        }

        [Fact]
        public void A_plugin_version_is_optional_and_an_absurd_one_does_not_stop_an_activation()
        {
            var reply = _service.ActivateAndSign(
                new ActivationRequest
                {
                    Code = _service.GiveOutACode(),
                    ServerId = "c5bc6e91458540caa295c4efdda1a58a",
                    PluginVersion = new string('v', 5000),
                },
                "10.0.0.1");

            Assert.True(reply.IsSuccess);
        }

        [Fact]
        public void No_failure_carries_a_licence()
        {
            Assert.Null(Activate("nonsense", "c5bc6e91458540caa295c4efdda1a58a").Licence);
            Assert.Null(Activate(RedemptionCode.Format(RedemptionCode.Generate()), "server").Licence);
        }

        private ActivationReply Activate(string code, string serverId)
        {
            return _service.Activations.Activate(
                new ActivationRequest { Code = code, ServerId = serverId },
                "10.0.0.1");
        }
    }
}
