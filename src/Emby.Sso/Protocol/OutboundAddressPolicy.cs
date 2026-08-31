using System;
using System.Net;
using System.Net.Sockets;

namespace Emby.Sso.Protocol
{
    /// <summary>
    /// What <see cref="OutboundAddressPolicy.Classify(IPAddress)"/> made of one
    /// address. Everything except <see cref="Permitted"/> is a refusal; the
    /// three that an operator can override are named separately from the ones
    /// nothing overrides, because <see cref="OutboundAddressPolicy.Permits"/>
    /// treats them differently and the refusal message has to say which kind
    /// this was.
    /// </summary>
    internal enum OutboundAddressOutcome
    {
        Permitted = 0,

        /// <summary>127.0.0.0/8 or ::1 - this server talking to itself.</summary>
        Loopback = 1,

        /// <summary>
        /// 169.254.0.0/16 or fe80::/10. Includes 169.254.169.254, the cloud
        /// instance metadata service, which is the single most valuable target
        /// a server-side request forgery has.
        /// </summary>
        LinkLocal = 2,

        /// <summary>
        /// RFC1918 (10/8, 172.16/12, 192.168/16), IPv6 unique-local (fc00::/7)
        /// or the deprecated site-local fec0::/10.
        /// </summary>
        PrivateNetwork = 3,

        /// <summary>
        /// RFC6598 carrier-grade NAT space, 100.64.0.0/10 - which is also what
        /// Tailscale hands out, so it is a plausible place for a home lab's
        /// identity provider to sit.
        /// </summary>
        SharedAddressSpace = 4,

        /// <summary>0.0.0.0/8 or ::, which name no host at all.</summary>
        Unspecified = 5,

        /// <summary>224.0.0.0/4 or ff00::/8.</summary>
        Multicast = 6,

        /// <summary>
        /// Documentation, benchmarking and future-use ranges: 192.0.0.0/24,
        /// 192.0.2.0/24, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24,
        /// 240.0.0.0/4 and the broadcast address.
        /// </summary>
        Reserved = 7,

        /// <summary>
        /// Not an address family this policy can reason about, so it cannot say
        /// the destination is public. Refused, because the fail-closed direction
        /// on an outbound-destination check is to refuse what is not understood.
        /// </summary>
        UnknownFamily = 8,
    }

    /// <summary>
    /// Decides whether the plugin may send an HTTP request to a given address.
    ///
    /// WHY THIS EXISTS. Every address this plugin fetches is chosen by somebody
    /// else: the issuer URL is typed by an administrator, and the JWKS URI and
    /// the token endpoint are whatever the discovery document at that issuer
    /// says they are. The fetches run inside the Emby server process, with the
    /// whole of that host's network reach and none of a browser's same-origin
    /// restraints. An administrator who pastes an issuer URL from a support
    /// forum, or an identity provider that is compromised later, can therefore
    /// aim this process at 127.0.0.1, at a router's admin page on 192.168.1.1,
    /// or at 169.254.169.254 - the cloud metadata service that hands out the
    /// instance's credentials. That is server-side request forgery, and the
    /// address, not the URL's spelling, is the thing that has to be checked:
    /// a perfectly ordinary-looking public hostname can resolve to 127.0.0.1.
    ///
    /// WHY IT IS NOT A HARD BLOCK. A great many legitimate operators run
    /// Authentik on a private address - that is the normal shape of a home lab,
    /// and refusing it outright would break more installations than it would
    /// protect. So the private-ish ranges are refused BY DEFAULT and permitted
    /// by one clearly named setting, and every refusal says which rule fired
    /// and how to permit it (see <see cref="Explain"/>). A guard that makes the
    /// plugin mysteriously stop working is worse than the risk it removes.
    ///
    /// WHAT THE SETTING DOES NOT COVER. Link-local, multicast, unspecified and
    /// reserved addresses stay refused whatever the setting says. Nobody runs
    /// an identity provider on 169.254.169.254; allowing it would hand away the
    /// exact thing the guard exists to protect, and there is no home-lab case
    /// on the other side of the trade.
    ///
    /// WHAT THIS CANNOT DO. Resolving a name here and connecting a moment later
    /// are two separate lookups, so a DNS server that answers differently the
    /// second time (DNS rebinding) is NOT stopped by this. Closing that needs
    /// the connection to be made to the address that was checked, which the
    /// netstandard2.0 HTTP stack gives no way to do. The guard raises the cost
    /// of a one-shot "point it at the metadata service" attack; it is not a
    /// substitute for network policy around the Emby host.
    /// </summary>
    internal static class OutboundAddressPolicy
    {
        /// <summary>
        /// The setting that permits the overridable ranges, spelled exactly as
        /// the configuration page spells it, because it is quoted into refusal
        /// messages an operator will go looking for on that page.
        /// </summary>
        public const string AllowanceSettingName =
            "Allow an identity provider on a private or loopback address";

        public static OutboundAddressOutcome Classify(IPAddress address)
        {
            if (address == null)
            {
                return OutboundAddressOutcome.UnknownFamily;
            }

            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
                return ClassifyV4(address.GetAddressBytes());
            }

            if (address.AddressFamily == AddressFamily.InterNetworkV6)
            {
                return ClassifyV6(address.GetAddressBytes());
            }

            return OutboundAddressOutcome.UnknownFamily;
        }

        /// <summary>
        /// Whether an outcome may proceed. Only the four ranges a real home lab
        /// might plausibly use are covered by the allowance; see the class
        /// summary for why the rest are not.
        /// </summary>
        public static bool Permits(OutboundAddressOutcome outcome, bool allowPrivateNetworks)
        {
            if (outcome == OutboundAddressOutcome.Permitted)
            {
                return true;
            }

            if (!allowPrivateNetworks)
            {
                return false;
            }

            return outcome == OutboundAddressOutcome.Loopback
                || outcome == OutboundAddressOutcome.PrivateNetwork
                || outcome == OutboundAddressOutcome.SharedAddressSpace;
        }

        /// <summary>Whether the allowance setting can permit this outcome at all.</summary>
        public static bool IsOverridable(OutboundAddressOutcome outcome)
        {
            return Permits(outcome, true) && outcome != OutboundAddressOutcome.Permitted;
        }

        /// <summary>
        /// The refusal, in one sentence an operator can act on: which address
        /// was refused, which rule refused it, and either the name of the
        /// setting that permits it or the fact that nothing does. This text
        /// reaches the server log; the browser only ever sees the generic
        /// user-safe reason.
        /// </summary>
        public static string Explain(string requestedUrl, IPAddress address, OutboundAddressOutcome outcome)
        {
            var url = LogSafeText.Flatten(requestedUrl);
            var literal = address == null ? "an address" : LogSafeText.Flatten(address.ToString());

            var remedy = IsOverridable(outcome)
                ? "If your identity provider really is at this address, tick '"
                  + AllowanceSettingName + "' on the plugin's configuration page."
                : "No setting permits this address.";

            return "refusing to fetch " + url + ": the host resolves to " + literal
                + ", which is " + Describe(outcome) + ". " + remedy;
        }

        /// <summary>The rule, named with the range it comes from.</summary>
        public static string Describe(OutboundAddressOutcome outcome)
        {
            switch (outcome)
            {
                case OutboundAddressOutcome.Permitted:
                    return "a public address";
                case OutboundAddressOutcome.Loopback:
                    return "a loopback address (127.0.0.0/8, ::1)";
                case OutboundAddressOutcome.LinkLocal:
                    return "a link-local address (169.254.0.0/16, fe80::/10) - the range that "
                        + "carries the 169.254.169.254 cloud metadata service";
                case OutboundAddressOutcome.PrivateNetwork:
                    return "a private address (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)";
                case OutboundAddressOutcome.SharedAddressSpace:
                    return "in carrier-grade NAT space (100.64.0.0/10)";
                case OutboundAddressOutcome.Unspecified:
                    return "the unspecified address (0.0.0.0/8, ::)";
                case OutboundAddressOutcome.Multicast:
                    return "a multicast address (224.0.0.0/4, ff00::/8)";
                case OutboundAddressOutcome.Reserved:
                    return "in a reserved or documentation range";
                default:
                    return "an address of a kind this plugin will not send requests to";
            }
        }

        private static OutboundAddressOutcome ClassifyV4(byte[] b)
        {
            if (b.Length != 4)
            {
                return OutboundAddressOutcome.UnknownFamily;
            }

            if (b[0] == 0)
            {
                return OutboundAddressOutcome.Unspecified;
            }

            if (b[0] == 127)
            {
                return OutboundAddressOutcome.Loopback;
            }

            if (b[0] == 10
                || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                || (b[0] == 192 && b[1] == 168))
            {
                return OutboundAddressOutcome.PrivateNetwork;
            }

            if (b[0] == 169 && b[1] == 254)
            {
                return OutboundAddressOutcome.LinkLocal;
            }

            if (b[0] == 100 && b[1] >= 64 && b[1] <= 127)
            {
                return OutboundAddressOutcome.SharedAddressSpace;
            }

            if ((b[0] == 192 && b[1] == 0 && b[2] == 0)
                || (b[0] == 192 && b[1] == 0 && b[2] == 2)
                || (b[0] == 198 && (b[1] == 18 || b[1] == 19))
                || (b[0] == 198 && b[1] == 51 && b[2] == 100)
                || (b[0] == 203 && b[1] == 0 && b[2] == 113))
            {
                return OutboundAddressOutcome.Reserved;
            }

            if (b[0] >= 224 && b[0] <= 239)
            {
                return OutboundAddressOutcome.Multicast;
            }

            if (b[0] >= 240)
            {
                return OutboundAddressOutcome.Reserved;
            }

            return OutboundAddressOutcome.Permitted;
        }

        private static OutboundAddressOutcome ClassifyV6(byte[] b)
        {
            if (b.Length != 16)
            {
                return OutboundAddressOutcome.UnknownFamily;
            }

            if (IsAllZero(b, 0, 16))
            {
                return OutboundAddressOutcome.Unspecified;
            }

            if (IsAllZero(b, 0, 15) && b[15] == 1)
            {
                return OutboundAddressOutcome.Loopback;
            }

            // An IPv6 address can carry an IPv4 one inside it, and every one of
            // these forms is a way to write "127.0.0.1" or "169.254.169.254"
            // that a check on the outer address alone would wave through. So the
            // embedded address is pulled out and classified as what it is.
            var embedded = EmbeddedV4(b);

            if (embedded != null)
            {
                return ClassifyV4(embedded);
            }

            if ((b[0] & 0xFE) == 0xFC)
            {
                return OutboundAddressOutcome.PrivateNetwork;
            }

            if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80)
            {
                return OutboundAddressOutcome.LinkLocal;
            }

            if (b[0] == 0xFE && (b[1] & 0xC0) == 0xC0)
            {
                // fec0::/10, site-local. Deprecated, but a stack that still
                // hands one out means the same thing a private address means.
                return OutboundAddressOutcome.PrivateNetwork;
            }

            if (b[0] == 0xFF)
            {
                return OutboundAddressOutcome.Multicast;
            }

            return OutboundAddressOutcome.Permitted;
        }

        /// <summary>
        /// The IPv4 address wrapped inside an IPv6 one, or null when there is
        /// none. Covers IPv4-mapped (::ffff:a.b.c.d), the deprecated
        /// IPv4-compatible form (::a.b.c.d), 6to4 (2002::/16), Teredo
        /// (2001:0::/32, whose embedded address is stored inverted) and the
        /// well-known NAT64 prefix (64:ff9b::/96).
        /// </summary>
        private static byte[] EmbeddedV4(byte[] b)
        {
            if (IsAllZero(b, 0, 10) && b[10] == 0xFF && b[11] == 0xFF)
            {
                return new[] { b[12], b[13], b[14], b[15] };
            }

            if (IsAllZero(b, 0, 12))
            {
                return new[] { b[12], b[13], b[14], b[15] };
            }

            if (b[0] == 0x20 && b[1] == 0x02)
            {
                return new[] { b[2], b[3], b[4], b[5] };
            }

            if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x00 && b[3] == 0x00)
            {
                return new[]
                {
                    (byte)(b[12] ^ 0xFF),
                    (byte)(b[13] ^ 0xFF),
                    (byte)(b[14] ^ 0xFF),
                    (byte)(b[15] ^ 0xFF),
                };
            }

            if (b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xFF && b[3] == 0x9B
                && IsAllZero(b, 4, 8))
            {
                return new[] { b[12], b[13], b[14], b[15] };
            }

            return null;
        }

        private static bool IsAllZero(byte[] b, int offset, int count)
        {
            for (var i = offset; i < offset + count; i++)
            {
                if (b[i] != 0)
                {
                    return false;
                }
            }

            return true;
        }
    }
}
