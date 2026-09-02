using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using Emby.Sso.LicenceService.Configuration;

namespace Emby.Sso.LicenceService.Admin
{
    /// <summary>
    /// Who is signed in, held on the server.
    ///
    /// THE COOKIE CARRIES A LOOKUP KEY AND NOTHING ELSE. It is 256 bits from the
    /// system CSPRNG and it means nothing away from this process's memory: it is
    /// not a signed token, it does not encode a username or an expiry, and there
    /// is no way to make one that this dictionary does not already know about.
    /// That is what makes <see cref="Destroy"/> a real logout - the state that
    /// authorises a request is here, so removing it ends the session for anyone
    /// still holding the cookie, which is the point of a logout on a page like
    /// this one.
    ///
    /// THE COOKIE NAME IS `__Host-` PREFIXED, and that is load-bearing rather
    /// than decorative. A browser will only accept a `__Host-` cookie that is
    /// Secure, has no Domain, and has Path=/, and it will not let a sibling or
    /// parent host set one. So the attributes the brief asks for are enforced by
    /// the browser as well as written by us, and a cookie planted from
    /// somewhere else on the parent domain cannot shadow this one. The cost is
    /// Path=/ - the cookie is attached to requests for /buy and /v1/activate
    /// too. Everything on this host is ours, the cookie is HttpOnly, and no
    /// route but /admin/* ever looks at it; the cookie-tossing immunity is worth
    /// more than the narrower path.
    ///
    /// Sessions live in memory only. A restart signs the operator out, which is
    /// correct: a licence service that survives a restart with its admin
    /// sessions intact has written them down somewhere, and the somewhere would
    /// be on the same disk as the signing key.
    /// </summary>
    public sealed class AdminSessions
    {
        /// <summary>
        /// See the class remarks for why the prefix is not cosmetic. There is no
        /// configuration that changes this name and no configuration that drops
        /// the prefix.
        /// </summary>
        public const string CookieName = "__Host-admin-session";

        /// <summary>256 bits. A session id is a bearer credential for this page.</summary>
        public const int IdBytes = 32;

        /// <summary>
        /// More than one operator, or one operator on a phone and a laptop, is
        /// fine; a thousand is a bug or an attack. The oldest goes when the cap
        /// is reached, so this cannot be used to grow memory.
        /// </summary>
        public const int MaximumSessions = 16;

        private readonly object _gate = new object();
        private readonly Dictionary<string, AdminSession> _sessions = new Dictionary<string, AdminSession>(StringComparer.Ordinal);
        private readonly AdminOptions _options;
        private readonly TimeProvider _time;

        public AdminSessions(AdminOptions options, TimeProvider time)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));
            _time = time ?? throw new ArgumentNullException(nameof(time));
        }

        public TimeSpan IdleTimeout => TimeSpan.FromMinutes(_options.IdleMinutes);

        public TimeSpan AbsoluteTimeout => TimeSpan.FromMinutes(_options.AbsoluteMinutes);

        public int Count
        {
            get
            {
                lock (_gate)
                {
                    return _sessions.Count;
                }
            }
        }

        /// <summary>
        /// A new session, after a correct password and never before one. There
        /// is no such thing as an anonymous session here to be promoted, which
        /// is the simplest defence against session fixation there is: the id
        /// that authorises a request has never been outside this process before
        /// the moment it is minted.
        /// </summary>
        public AdminSession Create(string clientKey)
        {
            var now = _time.GetUtcNow();

            lock (_gate)
            {
                SweepLocked(now);

                while (_sessions.Count >= MaximumSessions)
                {
                    var oldest = _sessions.OrderBy(pair => pair.Value.CreatedUtc).First().Key;

                    _sessions.Remove(oldest);
                }

                var session = new AdminSession
                {
                    Id = NewSecret(),
                    CsrfToken = NewSecret(),
                    CreatedUtc = now,
                    LastSeenUtc = now,
                    ClientKey = clientKey,
                };

                _sessions[session.Id] = session;

                return session;
            }
        }

        /// <summary>
        /// The session for a cookie, or null - absent, expired on idle, or
        /// expired on the absolute ceiling. Finding one touches it, so the idle
        /// clock measures idleness rather than age.
        ///
        /// An expired session is REMOVED here rather than merely reported, so
        /// the same cookie cannot be presented again after the clock moves back
        /// under some other timing.
        /// </summary>
        public AdminSession Find(string id)
        {
            if (string.IsNullOrEmpty(id))
            {
                return null;
            }

            var now = _time.GetUtcNow();

            lock (_gate)
            {
                SweepLocked(now);

                if (!_sessions.TryGetValue(id, out var session))
                {
                    return null;
                }

                session.LastSeenUtc = now;

                return session;
            }
        }

        /// <summary>
        /// Logout. Returns whether there was anything to destroy, so the audit
        /// line can tell a real logout from a stale cookie.
        /// </summary>
        public bool Destroy(string id)
        {
            if (string.IsNullOrEmpty(id))
            {
                return false;
            }

            lock (_gate)
            {
                return _sessions.Remove(id);
            }
        }

        private void SweepLocked(DateTimeOffset now)
        {
            var dead = _sessions
                .Where(pair => IsExpired(pair.Value, now))
                .Select(pair => pair.Key)
                .ToList();

            foreach (var id in dead)
            {
                _sessions.Remove(id);
            }
        }

        private bool IsExpired(AdminSession session, DateTimeOffset now)
        {
            return now - session.LastSeenUtc >= IdleTimeout || now - session.CreatedUtc >= AbsoluteTimeout;
        }

        internal static string NewSecret()
        {
            // Base64url: no padding, nothing that needs escaping in a cookie, an
            // HTML attribute or a form field.
            return Convert.ToBase64String(RandomNumberGenerator.GetBytes(IdBytes))
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        }
    }

    /// <summary>
    /// One signed-in operator. Everything that authorises a request lives here,
    /// on the server, including the CSRF token and the one-shot things the page
    /// shows exactly once.
    /// </summary>
    public sealed class AdminSession
    {
        /// <summary>How many unused form nonces one session may be holding.</summary>
        public const int MaximumNonces = 32;

        private readonly object _gate = new object();
        private readonly LinkedList<string> _nonces = new LinkedList<string>();

        /// <summary>The cookie value. Never logged, never rendered, never in a URL.</summary>
        public string Id { get; set; }

        /// <summary>
        /// The CSRF token, bound to this session and to no other. It is rendered
        /// into every form that changes something and compared in constant time
        /// on the way back. SameSite=Strict is also set on the cookie and is NOT
        /// what is relied on here: it is a browser behaviour with a history of
        /// exceptions, it does nothing for a request a browser does not label as
        /// cross-site, and it is not a thing this service can verify happened.
        /// </summary>
        public string CsrfToken { get; set; }

        public DateTimeOffset CreatedUtc { get; set; }

        public DateTimeOffset LastSeenUtc { get; set; }

        /// <summary>
        /// Where this session was created from, for the audit trail. It is NOT
        /// checked on later requests: a mobile operator whose address changes
        /// mid-session would be signed out by that check, and locking the only
        /// person who can fix this service out of it is the failure mode this
        /// design keeps refusing. A change is logged instead.
        /// </summary>
        public string ClientKey { get; set; }

        /// <summary>
        /// Something to be shown exactly once and then never again - the code a
        /// just-issued licence produced, or a code read back out of the outbox.
        /// It lives here, on the server, so that it is never in a URL, never in
        /// a redirect, and cannot be brought back by a refresh or the back
        /// button: the render consumes it.
        /// </summary>
        public AdminFlash Flash { get; set; }

        /// <summary>
        /// Hands out a one-shot token for a form that must not be submitted
        /// twice. See <see cref="ConsumeNonce"/>.
        /// </summary>
        public string IssueNonce()
        {
            var nonce = AdminSessions.NewSecret();

            lock (_gate)
            {
                _nonces.AddLast(nonce);

                while (_nonces.Count > MaximumNonces)
                {
                    _nonces.RemoveFirst();
                }
            }

            return nonce;
        }

        /// <summary>
        /// Spends a one-shot form token, or refuses.
        ///
        /// This is what stops a double-tapped Issue button minting two codes: a
        /// CSRF token is stable for the session and so cannot tell a second
        /// submission from a first, and a redirect after POST stops a refresh of
        /// the RESULT but not a back-and-resubmit of the FORM. The nonce is
        /// created when the form is rendered and removed when it is used, so the
        /// second arrival of the same form is refused - and refused before
        /// anything is created.
        /// </summary>
        public bool ConsumeNonce(string nonce)
        {
            if (string.IsNullOrEmpty(nonce))
            {
                return false;
            }

            lock (_gate)
            {
                for (var node = _nonces.First; node != null; node = node.Next)
                {
                    if (string.Equals(node.Value, nonce, StringComparison.Ordinal))
                    {
                        _nonces.Remove(node);

                        return true;
                    }
                }
            }

            return false;
        }

        /// <summary>Takes the one-shot payload, leaving nothing behind.</summary>
        public AdminFlash TakeFlash()
        {
            lock (_gate)
            {
                var flash = Flash;

                Flash = null;

                return flash;
            }
        }
    }

    /// <summary>
    /// A redemption code on its way to the screen, once.
    ///
    /// A code exists in the clear for exactly one moment - when it is created,
    /// or when it is read back out of the outbox file that holds it in the clear
    /// anyway - and that moment is the only chance anybody has to copy it. This
    /// carries it from the POST that produced it to the GET that shows it,
    /// through server memory rather than through a URL or a redirect, and it is
    /// gone the instant it has been rendered.
    /// </summary>
    public sealed class AdminFlash
    {
        /// <summary>The code, in the clear. Never logged, never audited, never in a URL.</summary>
        public string Code { get; set; }

        /// <summary>The hash tag, which IS safe to log and audit.</summary>
        public string Tag { get; set; }

        public string Licensee { get; set; }

        public int ActivationsAllowed { get; set; }

        public int LicenceDays { get; set; }

        /// <summary>Whether this came from issuing a code or from revealing an outbox line.</summary>
        public bool FromOutbox { get; set; }
    }
}
