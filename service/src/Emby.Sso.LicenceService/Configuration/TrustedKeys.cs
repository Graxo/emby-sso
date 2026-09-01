using System;
using System.Collections.Generic;
using Emby.Sso.Licensing;
using Microsoft.IdentityModel.Tokens;

namespace Emby.Sso.LicenceService.Configuration
{
    /// <summary>
    /// The public keys this service will accept a signed licence from, parsed
    /// once at startup.
    ///
    /// PUBLIC KEYS ONLY, and that is the whole point of the class existing:
    /// there is nowhere in this service that a private key belongs any more, and
    /// this is what an operator sets INSTEAD of mounting one. If the value they
    /// paste in carries private material, the service refuses to start and says
    /// so, rather than accepting it and quietly becoming able to sign again.
    ///
    /// It should hold the same set the plugin build was shipped with. When they
    /// disagree the failure is loud and early - an upload signed by a key this
    /// service does not know is refused on the operator's own screen - which is
    /// far better than the alternative, where a licence is stored, delivered,
    /// and refused on a customer's server days later.
    /// </summary>
    public sealed class TrustedKeys
    {
        public TrustedKeys(IReadOnlyList<JsonWebKey> keys)
        {
            Keys = keys ?? throw new ArgumentNullException(nameof(keys));

            if (keys.Count == 0)
            {
                throw new ArgumentException("a service with no trusted keys could never accept a licence", nameof(keys));
            }
        }

        public IReadOnlyList<JsonWebKey> Keys { get; }

        /// <summary>Parses LICENCE_PUBLIC_KEYS. Throws <see cref="FormatException"/> naming what is wrong.</summary>
        public static TrustedKeys Parse(string json)
        {
            return new TrustedKeys(TrustedLicenceKeys.Parse(json));
        }

        /// <summary>What a startup log line may say: which keys, by name, and nothing else.</summary>
        public string Describe()
        {
            var names = new List<string>(Keys.Count);

            foreach (var key in Keys)
            {
                names.Add(key.Kid);
            }

            return string.Join(", ", names);
        }
    }
}
