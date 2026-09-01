using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Emby.Sso.LicenceService.Admin;
using Emby.Sso.LicenceService.Configuration;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// The real service, with a real store and a real admin page, over a
    /// TestServer - the same wiring <c>Main</c> builds, because
    /// <c>Program.BuildApp</c> is what both call.
    ///
    /// Cookies are handled by hand rather than by an HttpClientHandler on
    /// purpose: half of what these tests are about is what the Set-Cookie header
    /// actually says, and a cookie container would swallow exactly that.
    /// </summary>
    internal sealed class AdminTestHost : IAsyncDisposable
    {
        /// <summary>Long enough to pass the strength rules, and obviously a test's.</summary>
        public const string Password = "test-admin-password-XZ42-not-real";

        private readonly TestService _service;
        private readonly WebApplication _app;
        private readonly HttpClient _client;

        private AdminTestHost(TestService service, WebApplication app, HttpClient client)
        {
            _service = service;
            _app = app;
            _client = client;
        }

        public TestService Service => _service;

        public TestClock Clock => _service.Clock;

        public ServiceOptions Options => _service.Options;

        /// <summary>The session cookie, as a browser would send it back. Null until a login succeeds.</summary>
        public string Cookie { get; set; }

        public static async Task<AdminTestHost> StartAsync(Action<ServiceOptions> configure = null)
        {
            var service = new TestService(options =>
            {
                options.PayPal.ClientId = null;
                options.PayPal.ClientSecret = null;
                options.Admin.PasswordHash = AdminPassword.Encode(Password);

                configure?.Invoke(options);
            });

            var app = Program.BuildApp(service.Options, builder =>
            {
                builder.WebHost.UseTestServer();

                // The service's own clock, so idle and absolute timeouts can be
                // tested without a test that sleeps.
                builder.Services.AddSingleton<TimeProvider>(service.Clock);
            });

            await app.StartAsync();

            return new AdminTestHost(service, app, app.GetTestClient());
        }

        public async Task<HttpResponseMessage> GetAsync(string path)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, path);

            Attach(request);

            return await _client.SendAsync(request);
        }

        /// <summary>
        /// A GET carrying one extra header, for the proxy-assertion the admin
        /// gate can be told to require.
        /// </summary>
        public async Task<HttpResponseMessage> GetWithHeaderAsync(string path, string name, string value)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, path);

            Attach(request);
            request.Headers.TryAddWithoutValidation(name, value);

            return await _client.SendAsync(request);
        }

        public async Task<HttpResponseMessage> PostAsync(string path, params (string Name, string Value)[] fields)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, path)
            {
                Content = new FormUrlEncodedContent(
                    fields.Select(field => new KeyValuePair<string, string>(field.Name, field.Value))),
            };

            Attach(request);

            return await _client.SendAsync(request);
        }

        /// <summary>Signs in and keeps the cookie. Returns the Set-Cookie header as it was sent.</summary>
        public async Task<string> LoginAsync(string password = Password)
        {
            using var response = await PostAsync("/admin/login", ("password", password));

            var header = response.Headers.TryGetValues("Set-Cookie", out var values)
                ? values.FirstOrDefault()
                : null;

            if (header != null)
            {
                var value = header.Split(';')[0];

                Cookie = value.StartsWith(AdminSessions.CookieName + "=", StringComparison.Ordinal)
                    && value.Length > AdminSessions.CookieName.Length + 1
                        ? value
                        : Cookie;
            }

            return header;
        }

        /// <summary>The CSRF token out of whatever page was just rendered.</summary>
        public static string CsrfIn(string html)
        {
            return Field(html, "csrf");
        }

        /// <summary>The one-shot form nonce out of whatever page was just rendered.</summary>
        public static string NonceIn(string html)
        {
            return Field(html, "nonce");
        }

        public async Task<string> BodyOfAsync(string path)
        {
            using var response = await GetAsync(path);

            return await response.Content.ReadAsStringAsync();
        }

        /// <summary>Everything the admin audit trail has recorded so far, as raw lines.</summary>
        public string AuditFile()
        {
            return File.Exists(_service.Options.AdminAuditPath)
                ? File.ReadAllText(_service.Options.AdminAuditPath)
                : string.Empty;
        }

        public async ValueTask DisposeAsync()
        {
            _client?.Dispose();

            if (_app != null)
            {
                await _app.StopAsync();
                await _app.DisposeAsync();
            }

            _service?.Dispose();
        }

        private void Attach(HttpRequestMessage request)
        {
            if (Cookie != null)
            {
                request.Headers.Add("Cookie", Cookie);
            }
        }

        private static string Field(string html, string name)
        {
            var match = Regex.Match(
                html,
                "name=\"" + Regex.Escape(name) + "\" value=\"([^\"]*)\"",
                RegexOptions.CultureInvariant);

            return match.Success ? match.Groups[1].Value : null;
        }
    }

    internal static class AdminTestExtensions
    {
        /// <summary>The Location a 303 pointed at, or null.</summary>
        public static string LocationOf(this HttpResponseMessage response)
        {
            return response.Headers.TryGetValues("Location", out var values) ? values.FirstOrDefault() : null;
        }

        public static string HeaderOf(this HttpResponseMessage response, string name)
        {
            if (response.Headers.TryGetValues(name, out var values))
            {
                return string.Join(", ", values);
            }

            return response.Content.Headers.TryGetValues(name, out var content)
                ? string.Join(", ", content)
                : null;
        }

        public static string SetCookieOf(this HttpResponseMessage response)
        {
            return response.Headers.TryGetValues("Set-Cookie", out var values) ? values.FirstOrDefault() : null;
        }

        public static string Number(this int value)
        {
            return value.ToString(CultureInfo.InvariantCulture);
        }
    }
}
