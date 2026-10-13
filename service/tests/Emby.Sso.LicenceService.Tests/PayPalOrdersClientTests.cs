using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.LicenceService.Configuration;
using Emby.Sso.LicenceService.PayPal;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// The checkout client, tested as far as it can be without PayPal.
    ///
    /// **THE LIVE PATH IS UNVERIFIED.** These tests prove the requests are built
    /// the way PayPal's documentation says to build them and that the response is
    /// read correctly. They cannot prove PayPal accepts them - no credentials, no
    /// route - so what they buy is that a mistake in the shape of the request is
    /// caught here rather than in the vendor's first sandbox run. The sandbox run
    /// is still required: docs/paypal-sandbox-checklist.md.
    /// </summary>
    public class PayPalOrdersClientTests
    {
        [Fact]
        public async Task The_token_request_is_client_credentials_with_basic_auth()
        {
            var transport = new RecordingTransport();
            var client = new PayPalOrdersClient(new HttpClient(transport), Options());

            await client.CreateOrderAsync(null, CancellationToken.None);

            var token = transport.Requests[0];

            Assert.Equal("https://api-m.sandbox.paypal.com/v1/oauth2/token", token.Url);
            Assert.Equal("Basic", token.AuthorizationScheme);
            Assert.Equal(
                Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("client-id:client-secret")),
                token.AuthorizationParameter);
            Assert.Contains("grant_type=client_credentials", token.Body, StringComparison.Ordinal);

            // The secret is in the header and nowhere else - not in the URL, not
            // in the body, because both of those are the things that end up in
            // logs.
            Assert.DoesNotContain("client-secret", token.Url, StringComparison.Ordinal);
            Assert.DoesNotContain("client-secret", token.Body, StringComparison.Ordinal);
        }

        [Fact]
        public async Task The_order_carries_the_configured_price_and_currency()
        {
            var transport = new RecordingTransport();
            var client = new PayPalOrdersClient(new HttpClient(transport), Options());

            await client.CreateOrderAsync(null, CancellationToken.None);

            var order = transport.Requests[1];

            Assert.Equal("https://api-m.sandbox.paypal.com/v2/checkout/orders", order.Url);
            Assert.Equal("Bearer", order.AuthorizationScheme);
            Assert.Equal("test-access-token", order.AuthorizationParameter);

            using var document = JsonDocument.Parse(order.Body);

            var amount = document.RootElement
                .GetProperty("purchase_units")[0]
                .GetProperty("amount");

            Assert.Equal("CAPTURE", document.RootElement.GetProperty("intent").GetString());
            Assert.Equal("19.00", amount.GetProperty("value").GetString());
            Assert.Equal("GBP", amount.GetProperty("currency_code").GetString());
        }

        [Fact]
        public async Task The_live_environment_uses_the_live_host()
        {
            var transport = new RecordingTransport();
            var options = Options();

            options.Environment = PayPalOptions.Live;

            var client = new PayPalOrdersClient(new HttpClient(transport), options);

            await client.CreateOrderAsync(null, CancellationToken.None);

            Assert.StartsWith("https://api-m.paypal.com/", transport.Requests[0].Url, StringComparison.Ordinal);
            Assert.StartsWith("https://api-m.paypal.com/", transport.Requests[1].Url, StringComparison.Ordinal);
        }

        [Fact]
        public async Task The_originating_server_id_travels_as_custom_id_and_is_omitted_when_absent()
        {
            var withServer = new RecordingTransport();

            await new PayPalOrdersClient(new HttpClient(withServer), Options())
                .CreateOrderAsync("c5bc6e91458540caa295c4efdda1a58a", CancellationToken.None);

            using (var document = JsonDocument.Parse(withServer.Requests[1].Body))
            {
                Assert.Equal(
                    "c5bc6e91458540caa295c4efdda1a58a",
                    document.RootElement.GetProperty("purchase_units")[0].GetProperty("custom_id").GetString());
            }

            var without = new RecordingTransport();

            await new PayPalOrdersClient(new HttpClient(without), Options())
                .CreateOrderAsync(null, CancellationToken.None);

            using (var document = JsonDocument.Parse(without.Requests[1].Body))
            {
                Assert.False(document.RootElement.GetProperty("purchase_units")[0].TryGetProperty("custom_id", out _));
            }
        }

        [Fact]
        public void The_approval_link_is_picked_out_of_the_response()
        {
            var order = PayPalOrdersClient.ReadOrder(
                "{\"id\":\"5O190127TN364715T\",\"links\":["
                + "{\"rel\":\"self\",\"href\":\"https://api-m.sandbox.paypal.com/v2/checkout/orders/5O1\"},"
                + "{\"rel\":\"approve\",\"href\":\"https://www.sandbox.paypal.com/checkoutnow?token=5O1\"}]}");

            Assert.Equal("5O190127TN364715T", order.OrderId);
            Assert.Equal("https://www.sandbox.paypal.com/checkoutnow?token=5O1", order.ApproveUrl);
        }

        [Fact]
        public void The_newer_payer_action_relation_is_understood_too()
        {
            var order = PayPalOrdersClient.ReadOrder(
                "{\"id\":\"5O1\",\"links\":[{\"rel\":\"payer-action\",\"href\":\"https://www.paypal.com/x\"}]}");

            Assert.Equal("https://www.paypal.com/x", order.ApproveUrl);
        }

        /// <summary>
        /// The approval link becomes a Location header pointing a paying
        /// customer's browser somewhere. Everything else in this client treats
        /// PayPal's responses as data rather than instructions, and a link out
        /// of a JSON body that redirects a buyer is exactly the kind of
        /// instruction that has to be checked before it is obeyed.
        /// </summary>
        [Theory]
        [InlineData("http://www.paypal.com/checkoutnow")]
        [InlineData("https://www.paypal.com.evil.example/checkoutnow")]
        [InlineData("https://evil.example/checkoutnow")]
        [InlineData("javascript:alert(1)")]
        [InlineData("/checkoutnow")]
        public void An_approval_link_that_is_not_paypal_over_https_is_refused(string href)
        {
            var error = Assert.Throws<PayPalApiException>(() => PayPalOrdersClient.ReadOrder(
                "{\"id\":\"5O1\",\"links\":[{\"rel\":\"approve\",\"href\":\"" + href + "\"}]}"));

            Assert.Contains("not a paypal.com address", error.Message, StringComparison.Ordinal);
            Assert.Contains("Nothing was charged", error.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void A_response_with_no_approval_link_is_an_error_and_not_a_half_built_order()
        {
            Assert.Throws<PayPalApiException>(() => PayPalOrdersClient.ReadOrder("{\"id\":\"5O1\",\"links\":[]}"));
            Assert.Throws<PayPalApiException>(() => PayPalOrdersClient.ReadOrder("{}"));
        }

        [Fact]
        public async Task Refused_credentials_are_an_error_that_does_not_repeat_PayPals_body()
        {
            var transport = new RecordingTransport
            {
                TokenStatus = HttpStatusCode.Unauthorized,
                TokenBody = "{\"error\":\"invalid_client\",\"error_description\":\"account 4XZ is restricted\"}",
            };

            var client = new PayPalOrdersClient(new HttpClient(transport), Options());

            var ex = await Assert.ThrowsAsync<PayPalApiException>(
                () => client.CreateOrderAsync(null, CancellationToken.None));

            Assert.Contains("401", ex.Message, StringComparison.Ordinal);
            Assert.DoesNotContain("account 4XZ", ex.Message, StringComparison.Ordinal);
        }

        [Fact]
        public async Task Checkout_without_credentials_refuses_before_it_makes_a_request()
        {
            var transport = new RecordingTransport();
            var options = Options();

            options.ClientSecret = null;

            var client = new PayPalOrdersClient(new HttpClient(transport), options);

            await Assert.ThrowsAsync<InvalidOperationException>(
                () => client.CreateOrderAsync(null, CancellationToken.None));

            Assert.Empty(transport.Requests);
        }

        [Fact]
        public async Task An_approved_order_is_captured_with_its_id_as_the_idempotency_key()
        {
            var transport = new RecordingTransport();
            var client = new PayPalOrdersClient(new HttpClient(transport), Options());

            var outcome = await client.CaptureOrderAsync("7TJ53096CB853001A", CancellationToken.None);

            var capture = transport.Requests[1];

            Assert.Equal(CaptureState.Completed, outcome.State);
            Assert.Equal("https://api-m.sandbox.paypal.com/v2/checkout/orders/7TJ53096CB853001A/capture", capture.Url);
            Assert.Equal("Bearer", capture.AuthorizationScheme);
            Assert.Equal("capture-7TJ53096CB853001A", capture.RequestId);
        }

        [Fact]
        public async Task A_declined_capture_is_a_refusal_and_an_already_captured_order_is_a_success()
        {
            var declined = new RecordingTransport
            {
                OrderStatus = (HttpStatusCode)422,
                OrderBody = "{\"name\":\"UNPROCESSABLE_ENTITY\",\"details\":[{\"issue\":\"INSTRUMENT_DECLINED\"}]}",
            };

            var refused = await new PayPalOrdersClient(new HttpClient(declined), Options())
                .CaptureOrderAsync("7TJ53096CB853001A", CancellationToken.None);

            Assert.Equal(CaptureState.Refused, refused.State);
            Assert.Equal("INSTRUMENT_DECLINED", refused.Issue);

            var again = new RecordingTransport
            {
                OrderStatus = (HttpStatusCode)422,
                OrderBody = "{\"details\":[{\"issue\":\"ORDER_ALREADY_CAPTURED\"}]}",
            };

            var completed = await new PayPalOrdersClient(new HttpClient(again), Options())
                .CaptureOrderAsync("7TJ53096CB853001A", CancellationToken.None);

            Assert.Equal(CaptureState.Completed, completed.State);
        }

        [Fact]
        public async Task A_server_error_on_capture_is_an_exception_because_it_says_nothing_about_the_money()
        {
            var transport = new RecordingTransport { OrderStatus = HttpStatusCode.ServiceUnavailable, OrderBody = "{}" };
            var client = new PayPalOrdersClient(new HttpClient(transport), Options());

            await Assert.ThrowsAsync<PayPalApiException>(
                () => client.CaptureOrderAsync("7TJ53096CB853001A", CancellationToken.None));
        }

        [Fact]
        public void A_pending_capture_is_read_from_the_capture_and_not_the_order()
        {
            var outcome = PayPalOrdersClient.ReadCapture(
                "{\"status\":\"COMPLETED\",\"purchase_units\":[{\"payments\":{\"captures\":[{\"status\":\"PENDING\"}]}}]}");

            Assert.Equal(CaptureState.Pending, outcome.State);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("../../v1/oauth2/token")]
        [InlineData("7TJ5%2F")]
        public async Task An_order_id_that_is_not_alphanumeric_is_refused_before_any_request(string orderId)
        {
            var transport = new RecordingTransport();
            var client = new PayPalOrdersClient(new HttpClient(transport), Options());

            await Assert.ThrowsAsync<ArgumentException>(() => client.CaptureOrderAsync(orderId, CancellationToken.None));

            Assert.Empty(transport.Requests);
        }

        private static PayPalOptions Options()
        {
            return new PayPalOptions
            {
                Environment = PayPalOptions.Sandbox,
                ClientId = "client-id",
                ClientSecret = "client-secret",
                WebhookId = "WH-1",
                Currency = "GBP",
                Price = "19.00",
                MinimumAmount = "19.00",
                ProductName = "Emby SSO plugin licence",
                ReturnUrl = "https://licence.example.com/buy/complete",
                CancelUrl = "https://licence.example.com/buy/cancelled",
            };
        }

        private sealed class RecordedRequest
        {
            public string Url { get; set; }

            public string Body { get; set; }

            public string AuthorizationScheme { get; set; }

            public string AuthorizationParameter { get; set; }

            public string RequestId { get; set; }
        }

        /// <summary>
        /// Stands in for PayPal. It answers the two calls the client makes and
        /// records exactly what was sent, which is the only part of this that can
        /// be checked without them.
        /// </summary>
        private sealed class RecordingTransport : HttpMessageHandler
        {
            public List<RecordedRequest> Requests { get; } = new List<RecordedRequest>();

            public HttpStatusCode TokenStatus { get; set; } = HttpStatusCode.OK;

            public string TokenBody { get; set; } = "{\"access_token\":\"test-access-token\",\"expires_in\":32400}";

            public HttpStatusCode? OrderStatus { get; set; }

            public string OrderBody { get; set; }

            protected override async Task<HttpResponseMessage> SendAsync(
                HttpRequestMessage request,
                CancellationToken cancellationToken)
            {
                Requests.Add(new RecordedRequest
                {
                    Url = request.RequestUri.ToString(),
                    Body = request.Content == null
                        ? null
                        : await request.Content.ReadAsStringAsync(cancellationToken),
                    AuthorizationScheme = request.Headers.Authorization?.Scheme,
                    AuthorizationParameter = request.Headers.Authorization?.Parameter,
                    RequestId = request.Headers.TryGetValues("PayPal-Request-Id", out var ids)
                        ? string.Join(",", ids)
                        : null,
                });

                if (request.RequestUri.AbsolutePath.EndsWith("/oauth2/token", StringComparison.Ordinal))
                {
                    return new HttpResponseMessage(TokenStatus)
                    {
                        Content = new StringContent(TokenBody, System.Text.Encoding.UTF8, "application/json"),
                    };
                }

                if (OrderStatus.HasValue)
                {
                    return new HttpResponseMessage(OrderStatus.Value)
                    {
                        Content = new StringContent(OrderBody, System.Text.Encoding.UTF8, "application/json"),
                    };
                }

                if (request.RequestUri.AbsolutePath.EndsWith("/capture", StringComparison.Ordinal))
                {
                    return new HttpResponseMessage(HttpStatusCode.Created)
                    {
                        Content = new StringContent(
                            "{\"id\":\"7TJ53096CB853001A\",\"status\":\"COMPLETED\",\"purchase_units\":[{\"payments\":"
                            + "{\"captures\":[{\"id\":\"3C679366HH908993F\",\"status\":\"COMPLETED\"}]}}]}",
                            System.Text.Encoding.UTF8,
                            "application/json"),
                    };
                }

                return new HttpResponseMessage(HttpStatusCode.Created)
                {
                    Content = new StringContent(
                        "{\"id\":\"5O190127TN364715T\",\"links\":["
                        + "{\"rel\":\"approve\",\"href\":\"https://www.sandbox.paypal.com/checkoutnow?token=5O1\"}]}",
                        System.Text.Encoding.UTF8,
                        "application/json"),
                };
            }
        }
    }
}
