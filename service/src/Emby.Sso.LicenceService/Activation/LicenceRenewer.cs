using System;
using Emby.Sso.LicenceService.Storage;
using Emby.Sso.Licensing;
using Microsoft.IdentityModel.Tokens;

namespace Emby.Sso.LicenceService.Activation
{
    /// <summary>
    /// Signs a licence to a later expiry for an activation that already has
    /// one, and records it in renewed_licences so that the status check and
    /// revocation know it exactly as they know the original.
    ///
    /// The one way a licence is extended. Two paths hand a licence to a
    /// server - the daily status check and a repeat activation - and both
    /// come here, so a renewed licence is the same thing whichever way it
    /// left: same licensee, same server (`aud` exactly as first activated),
    /// a row in renewed_licences, and activations.last_fingerprint pointing
    /// at it.
    /// </summary>
    public sealed class LicenceRenewer
    {
        private readonly LicenceStore _store;
        private readonly LicenceIssuer _issuer;

        public LicenceRenewer(LicenceStore store, JsonWebKey signingKey)
        {
            _store = store ?? throw new ArgumentNullException(nameof(store));
            _issuer = new LicenceIssuer(signingKey ?? throw new ArgumentNullException(nameof(signingKey)));
        }

        /// <summary>
        /// A licence like <paramref name="held"/>, issued <paramref name="now"/>
        /// and expiring at <paramref name="expires"/>. The caller decides that
        /// a renewal is due; this only makes and records it.
        /// </summary>
        public IssuedLicence Renew(HeldLicence held, DateTimeOffset expires, DateTimeOffset now)
        {
            if (held == null)
            {
                throw new ArgumentNullException(nameof(held));
            }

            var licence = _issuer.Issue(held.Licensee, held.ServerId, now, expires);

            _store.RecordRenewedLicence(held, licence);

            return licence;
        }
    }
}
