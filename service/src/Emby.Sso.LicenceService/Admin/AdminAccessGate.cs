using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Emby.Sso.LicenceService.Configuration;

namespace Emby.Sso.LicenceService.Admin
{
    /// <summary>
    /// What stands in front of the admin password.
    ///
    /// THE PROBLEM THIS SOLVES. /admin is on the public internet and, until
    /// this existed, one password was the entire boundary. That password is
    /// long, hashed with 210,000 rounds of PBKDF2, throttled on failure and
    /// capped in concurrency - and it is still one factor, held by one person,
    /// on machines that also read email. A single reused password, a single
    /// keylogger, a single shoulder-surf, and an attacker has the customer
    /// store, every signed licence in it, and the ability to stop new ones being
    /// issued.
    ///
    /// So the operator can require two more things, independently, both off by
    /// default and both fail-closed when on:
    ///
    ///   * that the request came from a network they named
    ///     (ADMIN_ALLOWED_CIDRS), which an attacker on the internet cannot
    ///     forge and which cannot be phished; and
    ///   * that it carries a header their own proxy adds
    ///     (ADMIN_REQUIRED_HEADER), which is where a Cloudflare Access
    ///     assertion, an oauth2-proxy header, a verified client certificate or
    ///     simply a long shared secret plugs in.
    ///
    /// A REFUSAL LOOKS LIKE THE PAGE DOES NOT EXIST. 404, not 403, and no hint
    /// that a restriction is what refused: somebody scanning for admin panels
    /// should learn nothing, including that there is one here to come back to
    /// from a different address.
    ///
    /// IT RUNS BEFORE EVERYTHING. Before the session lookup, before the login
    /// throttle, before any password verification - so a caller who fails it
    /// costs this service one address comparison, and can neither spend the
    /// throttle's budget nor make it do PBKDF2 work. That ordering is the
    /// second reason this class exists and is why it must not be moved.
    /// </summary>
    public sealed class AdminAccessGate
    {
        private readonly IReadOnlyList<Network> _networks;
        private readonly string _headerName;
        private readonly byte[] _headerValue;
        private readonly int _trustedProxyHops;

        public AdminAccessGate(AdminOptions admin, int trustedProxyHops)
        {
            if (admin == null)
            {
                throw new ArgumentNullException(nameof(admin));
            }

            _trustedProxyHops = trustedProxyHops;

            if (admin.HasNetworkRestriction)
            {
                if (!TryParseNetworks(admin.AllowedNetworks, out var networks, out var problem))
                {
                    // Unreachable through Main, which runs Problems() first. Here
                    // so that a caller which skips that check cannot end up with
                    // a gate that silently allows everything.
                    throw new ArgumentException("ADMIN_ALLOWED_CIDRS is not usable: " + problem, nameof(admin));
                }

                _networks = networks;
            }

            if (admin.HasRequiredHeader)
            {
                _headerName = admin.RequiredHeaderName;
                _headerValue = Encoding.UTF8.GetBytes(admin.RequiredHeaderValue ?? string.Empty);

                if (_headerValue.Length == 0)
                {
                    throw new ArgumentException(
                        "ADMIN_REQUIRED_HEADER is set with an empty value, which would admit any request that sets "
                        + "the header to nothing.",
                        nameof(admin));
                }
            }
        }

        /// <summary>True when neither guard is configured: the password is on its own.</summary>
        public bool IsOpen => _networks == null && _headerName == null;

        /// <summary>The header this gate reads, or null. Exposed so the request path can fetch exactly one.</summary>
        public string HeaderName => _headerName;

        /// <summary>
        /// Whether this request may see the admin page at all.
        ///
        /// <paramref name="peer"/> is the socket's own peer address and
        /// <paramref name="forwardedFor"/> the X-Forwarded-For header as sent.
        /// The address compared is chosen by the same trusted-hop rule the rate
        /// limiter uses, because getting two different answers to "who is this?"
        /// in one service is how a control ends up guarding nothing.
        /// </summary>
        public bool Admits(IPAddress peer, string forwardedFor, string headerValue)
        {
            if (_headerName != null && !HeaderMatches(headerValue))
            {
                return false;
            }

            if (_networks == null)
            {
                return true;
            }

            var address = ClientAddress(peer, forwardedFor, _trustedProxyHops);

            if (address == null)
            {
                // No usable address means the network check cannot be made, and
                // a check that cannot be made has not passed. Fail closed.
                return false;
            }

            foreach (var network in _networks)
            {
                if (network.Contains(address))
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Constant-time, and length-independent only up to leaking the length -
        /// which is not a secret worth protecting when the value is a shared
        /// secret of the operator's own choosing.
        /// </summary>
        private bool HeaderMatches(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return false;
            }

            var given = Encoding.UTF8.GetBytes(value);

            return CryptographicOperations.FixedTimeEquals(given, _headerValue);
        }

        /// <summary>
        /// Which address to hold this request to.
        ///
        /// With no trusted proxies the socket's peer is the client and nothing a
        /// caller sends can change that. With N trusted proxies, the Nth entry
        /// from the RIGHT of X-Forwarded-For is the last one a proxy we trust
        /// wrote; everything to the left of it was written by somebody we do not
        /// trust and is ignored. Getting the hop count too HIGH is the dangerous
        /// direction - a caller could then choose their own apparent address -
        /// which is why it defaults to 0 and why this reads from the right.
        /// </summary>
        internal static IPAddress ClientAddress(IPAddress peer, string forwardedFor, int trustedProxyHops)
        {
            if (trustedProxyHops <= 0 || string.IsNullOrWhiteSpace(forwardedFor))
            {
                return Normalise(peer);
            }

            var hops = forwardedFor.Split(',');
            var index = hops.Length - trustedProxyHops;

            if (index < 0 || index >= hops.Length)
            {
                // The chain is shorter than the configured number of proxies, so
                // this request did not come through them. Fall back to the peer,
                // which for a request that really did arrive through the proxy is
                // the proxy itself - and is therefore refused unless the proxy's
                // own address was allowed. Fail closed, again.
                return Normalise(peer);
            }

            return IPAddress.TryParse(hops[index].Trim(), out var address) ? Normalise(address) : null;
        }

        /// <summary>
        /// ::ffff:203.0.113.4 and 203.0.113.4 are the same host, and an operator
        /// who allowed one should not find the other refused because Kestrel is
        /// listening on a dual-stack socket.
        /// </summary>
        private static IPAddress Normalise(IPAddress address)
        {
            if (address == null)
            {
                return null;
            }

            return address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
        }

        /// <summary>
        /// Parses "10.0.0.0/8, 203.0.113.4, ::1/128". A bare address means the
        /// single host - the /32 or /128 - because that is what an operator
        /// typing one address means, and requiring them to write the suffix is
        /// how a restriction gets turned off in frustration.
        /// </summary>
        public static bool TryParseNetworks(string value, out IReadOnlyList<Network> networks, out string problem)
        {
            networks = null;
            problem = null;

            var parsed = new List<Network>();

            foreach (var part in (value ?? string.Empty).Split(','))
            {
                var text = part.Trim();

                if (text.Length == 0)
                {
                    continue;
                }

                var slash = text.IndexOf('/');
                var addressText = slash < 0 ? text : text.Substring(0, slash);

                if (!IPAddress.TryParse(addressText, out var address))
                {
                    problem = "'" + text + "' is not an IP address or CIDR range";

                    return false;
                }

                address = Normalise(address);

                var full = address.GetAddressBytes().Length * 8;
                var prefix = full;

                if (slash >= 0)
                {
                    var suffix = text.Substring(slash + 1);

                    if (!int.TryParse(suffix, NumberStyles.Integer, CultureInfo.InvariantCulture, out prefix)
                        || prefix < 0
                        || prefix > full)
                    {
                        problem = "'" + text + "' has a prefix length that is not between 0 and "
                            + full.ToString(CultureInfo.InvariantCulture);

                        return false;
                    }
                }

                parsed.Add(new Network(address, prefix));
            }

            if (parsed.Count == 0)
            {
                problem = "it lists no networks. Leave the variable unset to turn the restriction off, "
                    + "rather than setting it to something empty.";

                return false;
            }

            networks = parsed;

            return true;
        }

        /// <summary>One CIDR range, compared bit by bit.</summary>
        public sealed class Network
        {
            private readonly byte[] _address;
            private readonly int _prefix;

            public Network(IPAddress address, int prefix)
            {
                _address = address.GetAddressBytes();
                _prefix = prefix;
            }

            public bool Contains(IPAddress candidate)
            {
                var bytes = candidate.GetAddressBytes();

                // An IPv4 range never contains an IPv6 address and the other way
                // round. Comparing them by length would silently match nothing;
                // comparing them by value would be worse.
                if (bytes.Length != _address.Length)
                {
                    return false;
                }

                var whole = _prefix / 8;
                var bits = _prefix % 8;

                for (var i = 0; i < whole; i++)
                {
                    if (bytes[i] != _address[i])
                    {
                        return false;
                    }
                }

                if (bits == 0)
                {
                    return true;
                }

                var mask = (byte)(0xFF << (8 - bits));

                return (bytes[whole] & mask) == (_address[whole] & mask);
            }
        }
    }
}
