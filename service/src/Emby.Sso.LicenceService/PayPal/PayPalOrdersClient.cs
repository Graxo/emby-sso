using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Emby.Sso.LicenceService.Configuration;

namespace Emby.Sso.LicenceService.PayPal
{
    /// <summary>
    /// Starts a purchase: creates a PayPal order and hands back the URL the
    /// buyer is sent to.
    ///
    /// **UNVERIFIED.** Not one line of this has spoken to PayPal. It was written
    /// from PayPal's Orders v2 documentation in an environment with no
    /// credentials and no route to their API, so what is proven here is only
    /// what a test can prove without them: that the token request is
    /// client_credentials with HTTP basic auth, that the order body carries the
    /// configured price and currency, that the approval link is picked out of
    /// the response, and that an error response becomes an exception rather than
    /// a half-built order. Whether PayPal accepts these requests is confirmed by
    /// the sandbox run in docs/paypal-sandbox-checklist.md and nowhere else.
    ///
    /// Nothing here is on the security path. Creating an order commits nobody to
    /// anything; a licence code is created only by the webhook, only after the
    /// signature verifies, and only for a capture that really completed. A buyer
    /// who tampers with a checkout gets a bad order and no code.
    /// </summary>
    public sealed class PayPalOrdersClient
    {
        private readonly HttpClient _http;
        private readonly PayPalOptions _options;

        public PayPalOrdersClient(HttpClient http, PayPalOptions options)
        {
            _http = http ?? throw new ArgumentNullException(nameof(http));
            _options = options ?? throw new ArgumentNullException(nameof(options));
        }

        /// <summary>
        /// <paramref name="originServerId"/> is carried to PayPal as the purchase
        /// unit's custom_id and comes back on the webhook, so a support question
        /// can be answered with "this purchase was started from that server". It
        /// is metadata and nothing else: the code it eventually buys is not bound
        /// to that server, and the licence binds to whichever server the code is
        /// activated on. It arrives from a query string, so the caller has
        /// already validated it; PayPal caps custom_id at 127 characters.
        /// </summary>
        public async Task<CheckoutOrder> CreateOrderAsync(string originServerId, CancellationToken cancellationToken)
        {
            if (!_options.CheckoutConfigured)
            {
                throw new InvalidOperationException(
                    "checkout needs PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET and PAYPAL_PRICE");
            }

            var token = await GetAccessTokenAsync(cancellationToken).ConfigureAwait(false);

            var purchaseUnit = new Dictionary<string, object>
            {
                ["description"] = _options.ProductName,
                ["amount"] = new Dictionary<string, string>
                {
                    ["currency_code"] = _options.Currency,
                    ["value"] = _options.Price,
                },
            };

            if (!string.IsNullOrWhiteSpace(originServerId))
            {
                purchaseUnit["custom_id"] = originServerId;
            }

            var body = JsonSerializer.Serialize(new Dictionary<string, object>
            {
                ["intent"] = "CAPTURE",
                ["purchase_units"] = new[] { purchaseUnit },
                ["application_context"] = new Dictionary<string, string>
                {
                    ["brand_name"] = _options.ProductName,
                    ["user_action"] = "PAY_NOW",
                    ["return_url"] = _options.ReturnUrl ?? string.Empty,
                    ["cancel_url"] = _options.CancelUrl ?? string.Empty,
                },
            });

            using var request = new HttpRequestMessage(HttpMethod.Post, _options.ApiBase + "/v2/checkout/orders")
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
            };

            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

            using var response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);

            var text = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                throw new PayPalApiException(
                    "PayPal refused to create the order (" + (int)response.StatusCode + ").");
            }

            return ReadOrder(text);
        }

        internal static CheckoutOrder ReadOrder(string json)
        {
            using var document = JsonDocument.Parse(json);

            var root = document.RootElement;

            var id = root.TryGetProperty("id", out var idValue) && idValue.ValueKind == JsonValueKind.String
                ? idValue.GetString()
                : null;

            string approve = null;

            if (root.TryGetProperty("links", out var links) && links.ValueKind == JsonValueKind.Array)
            {
                foreach (var link in links.EnumerateArray())
                {
                    if (link.ValueKind != JsonValueKind.Object
                        || !link.TryGetProperty("rel", out var rel)
                        || rel.ValueKind != JsonValueKind.String)
                    {
                        continue;
                    }

                    var relation = rel.GetString();

                    // "approve" is what Orders v2 returns; "payer-action" is what
                    // the newer payment-source flows return for the same thing.
                    if (!string.Equals(relation, "approve", StringComparison.OrdinalIgnoreCase)
                        && !string.Equals(relation, "payer-action", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    if (link.TryGetProperty("href", out var href) && href.ValueKind == JsonValueKind.String)
                    {
                        approve = href.GetString();

                        break;
                    }
                }
            }

            if (string.IsNullOrEmpty(id) || string.IsNullOrEmpty(approve))
            {
                throw new PayPalApiException("PayPal's order response carried no id or no approval link.");
            }

            // THE BUYER IS REDIRECTED HERE, so it is checked before it is
            // handed back. Everything else in this file treats PayPal's
            // responses as data rather than instructions - the webhook verifier
            // and the certificate source both refuse a URL that is not a
            // paypal.com name for the same reason - and a link out of a JSON
            // body that becomes a Location header is exactly that kind of
            // instruction. The browser refuses a non-PayPal hop anyway, because
            // the buy page's form-action names one origin, but a refusal here
            // says why in the log instead of only in somebody's console.
            if (!IsPayPalCheckout(approve))
            {
                throw new PayPalApiException(
                    "PayPal's order response pointed the buyer at '" + approve + "', which is not a paypal.com "
                    + "address. Nothing was charged and the buyer was not sent there.");
            }

            return new CheckoutOrder(id, approve);
        }

        /// <summary>
        /// https, and a host that is paypal.com or below it. The same rule as
        /// <see cref="PayPalWebhookVerifier"/> applies to the certificate URL,
        /// and for the same reason.
        /// </summary>
        private static bool IsPayPalCheckout(string url)
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var parsed)
                || !string.Equals(parsed.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            var host = parsed.Host;

            return string.Equals(host, "paypal.com", StringComparison.OrdinalIgnoreCase)
                || host.EndsWith(".paypal.com", StringComparison.OrdinalIgnoreCase);
        }

        private async Task<string> GetAccessTokenAsync(CancellationToken cancellationToken)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, _options.ApiBase + "/v1/oauth2/token")
            {
                Content = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("grant_type", "client_credentials"),
                }),
            };

            // Basic auth over the client id and secret, per PayPal's docs. The
            // secret never appears in a URL or a log line: it is in this header
            // and in the environment, and nowhere else.
            request.Headers.Authorization = new AuthenticationHeaderValue(
                "Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes(_options.ClientId + ":" + _options.ClientSecret)));

            using var response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);

            var text = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                // A 401 here is nearly always one thing, and it is not a typo.
                // PayPal's sandbox and live systems have entirely separate
                // credentials, and each rejects the other's with exactly this
                // status - so a working set of live keys against PAYPAL_ENV
                // =sandbox looks identical to a set that was mistyped. Say so,
                // because the difference is invisible from the response and
                // costs an hour to find otherwise.
                var hint = response.StatusCode == System.Net.HttpStatusCode.Unauthorized
                    ? " PAYPAL_ENV is '" + _options.Environment + "', so these were sent to " + _options.ApiBase
                      + ". Sandbox and live credentials are separate and each refuses the other's:"
                      + " check the credentials came from the '" + _options.Environment
                      + "' side of the PayPal developer dashboard, not the other one."
                    : string.Empty;

                throw new PayPalApiException(
                    "PayPal refused the API credentials (" + (int)response.StatusCode + ")." + hint);
            }

            using var document = JsonDocument.Parse(text);

            if (!document.RootElement.TryGetProperty("access_token", out var token)
                || token.ValueKind != JsonValueKind.String)
            {
                throw new PayPalApiException("PayPal's token response carried no access_token.");
            }

            return token.GetString();
        }
    }

    public sealed class CheckoutOrder
    {
        public CheckoutOrder(string orderId, string approveUrl)
        {
            OrderId = orderId;
            ApproveUrl = approveUrl;
        }

        public string OrderId { get; }

        public string ApproveUrl { get; }
    }

    /// <summary>
    /// Deliberately carries no PayPal response body: those can contain
    /// account-level detail, and this exception's message reaches a log the
    /// vendor may paste into a support thread. The status code is enough to say
    /// what to look at.
    /// </summary>
    public sealed class PayPalApiException : Exception
    {
        public PayPalApiException(string message)
            : base(message)
        {
        }
    }
}
