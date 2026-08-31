using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Emby.Sso.Protocol
{
    /// <summary>
    /// A request this plugin refused to send. Carries the operator-facing
    /// sentence built by <see cref="OutboundAddressPolicy.Explain"/> or
    /// <see cref="OutboundRedirectPolicy.Explain"/>, which names the rule that
    /// fired and, where one exists, the setting that permits it.
    ///
    /// It is NOT an <see cref="SsoException"/>, because it is thrown from
    /// inside the HTTP stack, several frames below anything that knows whether
    /// a browser is waiting. <see cref="Find"/> lets the layer that does know
    /// pull it back out of whatever the stack wrapped it in.
    ///
    /// A refusal here is emphatically not "the provider could not be reached":
    /// nothing was sent, the provider had no part in it, and the fix is a
    /// setting rather than a network. Callers must translate it into an
    /// ordinary <see cref="SsoException"/> and never into
    /// <see cref="SsoException.Unreachable"/> - see the note on
    /// <see cref="SsoException.ProviderUnreachable"/> for why that direction is
    /// the fail-closed one.
    /// </summary>
    internal sealed class OutboundRefusedException : Exception
    {
        public OutboundRefusedException(string message)
            : base(message)
        {
        }

        /// <summary>
        /// The refusal buried anywhere inside <paramref name="exception"/>, or
        /// null. HttpClient and IdentityModel's ConfigurationManager both wrap
        /// what handlers throw, sometimes twice, so the whole chain - including
        /// every branch of an AggregateException - is searched.
        /// </summary>
        public static OutboundRefusedException Find(Exception exception)
        {
            if (exception == null)
            {
                return null;
            }

            if (exception is OutboundRefusedException refused)
            {
                return refused;
            }

            if (exception is AggregateException aggregate)
            {
                foreach (var inner in aggregate.InnerExceptions)
                {
                    var found = Find(inner);

                    if (found != null)
                    {
                        return found;
                    }
                }

                return null;
            }

            return Find(exception.InnerException);
        }
    }

    /// <summary>
    /// The one place every outbound HTTP request this plugin makes has to pass
    /// through: the discovery document, the JWKS, and the token endpoint alike.
    ///
    /// It does two things the HTTP stack will not do on its own.
    ///
    /// FIRST, it resolves the destination and refuses addresses that point back
    /// inside the network the Emby server sits in - see
    /// <see cref="OutboundAddressPolicy"/> for the threat and for why the
    /// private ranges are an operator-visible allowance rather than a block.
    /// Placing the check here rather than at each call site is deliberate: the
    /// token endpoint and the JWKS URI are read out of a discovery document
    /// this plugin did not write, and a check that has to be remembered at each
    /// new fetch is a check that will eventually be forgotten at one of them.
    ///
    /// SECOND, it takes over redirect handling. <see cref="HttpClientHandler"/>
    /// follows redirects silently, which would let one 302 carry any of those
    /// fetches to an address nobody configured and past the check above. So the
    /// transport handler is constructed with AllowAutoRedirect off and the hops
    /// are followed here, one at a time, each one re-checked against both
    /// policies - and no redirect is followed at all on a request that carries
    /// a credential.
    /// </summary>
    internal sealed class OutboundGuardHandler : DelegatingHandler
    {
        private readonly Func<bool> _allowPrivateNetworks;
        private readonly Func<string, Task<IPAddress[]>> _resolve;

        public OutboundGuardHandler(HttpMessageHandler innerHandler, Func<bool> allowPrivateNetworks)
            : this(innerHandler, allowPrivateNetworks, null)
        {
        }

        /// <param name="resolver">
        /// Name-to-address lookup. Defaults to DNS; the tests substitute one so
        /// that "a public name that resolves to a private address" can be
        /// exercised without depending on what any real name resolves to today.
        /// </param>
        public OutboundGuardHandler(
            HttpMessageHandler innerHandler,
            Func<bool> allowPrivateNetworks,
            Func<string, Task<IPAddress[]>> resolver)
            : base(innerHandler)
        {
            _allowPrivateNetworks = allowPrivateNetworks ?? throw new ArgumentNullException(nameof(allowPrivateNetworks));
            _resolve = resolver ?? (host => Dns.GetHostAddressesAsync(host));
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            // One read for the whole chain, so a settings save racing a redirect
            // cannot have one hop judged under one allowance and the next under
            // another.
            var allowPrivateNetworks = _allowPrivateNetworks();

            // The origin every hop is measured against is the one that was
            // configured, not the previous hop - see OutboundRedirectPolicy.
            var origin = request.RequestUri;
            var current = request;
            var hops = 0;

            while (true)
            {
                await GuardAddressAsync(current.RequestUri, allowPrivateNetworks).ConfigureAwait(false);

                var response = await base.SendAsync(current, cancellationToken).ConfigureAwait(false);

                if (!IsRedirect(response.StatusCode))
                {
                    return response;
                }

                // A redirect on anything but a GET means re-sending a body that
                // holds an authorization code, the client secret, or - on the
                // native path - a user's actual password. There is no address
                // worth following for that, so the chain stops here rather than
                // being judged on where it points.
                if (current.Method != HttpMethod.Get)
                {
                    var method = current.Method.Method;
                    response.Dispose();
                    DisposeIfFollowUp(current, request);

                    throw new OutboundRefusedException(
                        "refusing to follow a redirect returned for a " + method + " to "
                        + LogSafeText.Flatten(origin.ToString())
                        + ": that request carries a credential, and this plugin will not re-send it "
                        + "to a second address. Configure the address the provider serves its token "
                        + "endpoint from directly.");
                }

                if (hops >= OutboundRedirectPolicy.MaxRedirects)
                {
                    response.Dispose();
                    DisposeIfFollowUp(current, request);

                    throw new OutboundRefusedException(
                        "refusing to follow more than " + OutboundRedirectPolicy.MaxRedirects
                        + " redirects from " + LogSafeText.Flatten(origin.ToString()) + ".");
                }

                var location = ReadLocation(response);
                var target = ResolveLocation(current.RequestUri, location);
                var outcome = OutboundRedirectPolicy.Classify(origin, target);

                if (outcome != OutboundRedirectOutcome.Permitted)
                {
                    response.Dispose();
                    DisposeIfFollowUp(current, request);

                    throw new OutboundRefusedException(
                        OutboundRedirectPolicy.Explain(origin, location, outcome));
                }

                response.Dispose();

                var next = BuildFollowUp(current, target);
                DisposeIfFollowUp(current, request);
                current = next;
                hops++;
            }
        }

        private async Task GuardAddressAsync(Uri uri, bool allowPrivateNetworks)
        {
            if (uri == null || !uri.IsAbsoluteUri
                || !(string.Equals(uri.Scheme, "https", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(uri.Scheme, "http", StringComparison.OrdinalIgnoreCase)))
            {
                throw new OutboundRefusedException(
                    "refusing to fetch " + LogSafeText.Flatten(uri == null ? "(no address)" : uri.ToString())
                    + ": only absolute http and https URLs are fetched.");
            }

            var host = uri.DnsSafeHost;
            IPAddress[] addresses;

            if (IPAddress.TryParse(host, out var literal))
            {
                addresses = new[] { literal };
            }
            else
            {
                // A lookup that FAILS is deliberately not caught: that is a
                // provider this server could not reach, which the caller has to
                // be able to tell apart from a destination this plugin refused.
                // Only a lookup that succeeds is judged here.
                addresses = await _resolve(host).ConfigureAwait(false);
            }

            if (addresses == null || addresses.Length == 0)
            {
                throw new OutboundRefusedException(
                    "refusing to fetch " + LogSafeText.Flatten(uri.ToString())
                    + ": the host name resolved to no address at all, so where the request "
                    + "would go could not be checked.");
            }

            // EVERY address, not the first one that works. A name that answers
            // with one public address and one loopback address is a name that
            // can be connected to over the loopback address, and which of them
            // the stack picks is not this code's decision to make.
            foreach (var address in addresses)
            {
                var outcome = OutboundAddressPolicy.Classify(address);

                if (!OutboundAddressPolicy.Permits(outcome, allowPrivateNetworks))
                {
                    throw new OutboundRefusedException(
                        OutboundAddressPolicy.Explain(uri.ToString(), address, outcome));
                }
            }
        }

        private static bool IsRedirect(HttpStatusCode status)
        {
            var code = (int)status;

            return code == 300 || code == 301 || code == 302 || code == 303 || code == 307 || code == 308;
        }

        /// <summary>
        /// The raw Location header. Read through TryGetValues rather than the
        /// typed property because a malformed value makes the typed one throw,
        /// and a malformed Location is a refusal to describe, not a crash.
        /// </summary>
        private static string ReadLocation(HttpResponseMessage response)
        {
            if (response.Headers.TryGetValues("Location", out IEnumerable<string> values))
            {
                foreach (var value in values)
                {
                    return value;
                }
            }

            return null;
        }

        private static Uri ResolveLocation(Uri current, string location)
        {
            if (string.IsNullOrWhiteSpace(location))
            {
                return null;
            }

            return Uri.TryCreate(current, location, out var absolute) ? absolute : null;
        }

        private static HttpRequestMessage BuildFollowUp(HttpRequestMessage current, Uri target)
        {
            var next = new HttpRequestMessage(HttpMethod.Get, target);

            foreach (var header in current.Headers)
            {
                // Authorization is never carried onto a follow-up. The hop is
                // same-origin by the time this runs, so nothing is leaked by
                // copying it - it is dropped because a redirect is the provider
                // asking for the request again, not for the credential again.
                if (string.Equals(header.Key, "Authorization", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                next.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }

            return next;
        }

        /// <summary>
        /// Disposes a request this handler built, never the one the caller
        /// handed in - HttpClient owns that one and disposes it itself.
        /// </summary>
        private static void DisposeIfFollowUp(HttpRequestMessage current, HttpRequestMessage original)
        {
            if (!ReferenceEquals(current, original))
            {
                current.Dispose();
            }
        }
    }
}
