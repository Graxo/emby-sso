using System;
using System.Collections.Generic;
using Emby.Sso.LicenceService.Admin;
using Emby.Sso.LicenceService.Configuration;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// Sessions, held on the server.
    ///
    /// What is being held up here is that the cookie is a lookup key and nothing
    /// else: every one of these tests fails if the state that authorises a
    /// request moves into the cookie, or if a timeout stops being enforced on
    /// the way in.
    /// </summary>
    public class AdminSessionTests
    {
        private static readonly DateTimeOffset Start = new DateTimeOffset(2026, 3, 1, 9, 0, 0, TimeSpan.Zero);

        private static AdminSessions Make(TestClock clock, int idle = 30, int absolute = 480)
        {
            return new AdminSessions(
                new AdminOptions { IdleMinutes = idle, AbsoluteMinutes = absolute },
                clock);
        }

        [Fact]
        public void A_session_id_is_long_and_never_repeats()
        {
            var sessions = Make(new TestClock(Start));
            var seen = new HashSet<string>(StringComparer.Ordinal);

            for (var i = 0; i < 12; i++)
            {
                var session = sessions.Create("10.0.0.1");

                Assert.True(session.Id.Length >= 40, "a session id must carry at least 256 bits");
                Assert.True(seen.Add(session.Id), "a session id repeated");
                Assert.True(seen.Add(session.CsrfToken), "a CSRF token repeated, or matched a session id");
            }
        }

        [Fact]
        public void A_cookie_that_names_no_session_authorises_nothing()
        {
            var sessions = Make(new TestClock(Start));

            sessions.Create("10.0.0.1");

            Assert.Null(sessions.Find("not-a-session-id"));
            Assert.Null(sessions.Find(string.Empty));
            Assert.Null(sessions.Find(null));
        }

        [Fact]
        public void A_session_left_alone_past_the_idle_timeout_is_gone()
        {
            var clock = new TestClock(Start);
            var sessions = Make(clock, idle: 30);
            var session = sessions.Create("10.0.0.1");

            clock.Advance(TimeSpan.FromMinutes(29));

            Assert.NotNull(sessions.Find(session.Id));

            clock.Advance(TimeSpan.FromMinutes(31));

            Assert.Null(sessions.Find(session.Id));
            Assert.Equal(0, sessions.Count);
        }

        [Fact]
        public void Using_a_session_keeps_it_alive_against_the_idle_clock()
        {
            var clock = new TestClock(Start);
            var sessions = Make(clock, idle: 30);
            var session = sessions.Create("10.0.0.1");

            for (var i = 0; i < 6; i++)
            {
                clock.Advance(TimeSpan.FromMinutes(20));

                Assert.NotNull(sessions.Find(session.Id));
            }
        }

        /// <summary>
        /// The absolute ceiling is the one activity cannot extend. Remove it and
        /// this fails: the session above stays alive forever on a 20-minute
        /// heartbeat.
        /// </summary>
        [Fact]
        public void No_amount_of_use_gets_a_session_past_the_absolute_timeout()
        {
            var clock = new TestClock(Start);
            var sessions = Make(clock, idle: 30, absolute: 120);
            var session = sessions.Create("10.0.0.1");

            for (var i = 0; i < 5; i++)
            {
                clock.Advance(TimeSpan.FromMinutes(20));
                sessions.Find(session.Id);
            }

            clock.Advance(TimeSpan.FromMinutes(21));

            Assert.Null(sessions.Find(session.Id));
        }

        [Fact]
        public void Destroying_a_session_ends_it_for_whoever_still_holds_the_cookie()
        {
            var sessions = Make(new TestClock(Start));
            var session = sessions.Create("10.0.0.1");

            Assert.True(sessions.Destroy(session.Id));
            Assert.Null(sessions.Find(session.Id));
            Assert.False(sessions.Destroy(session.Id));
        }

        [Fact]
        public void The_number_of_live_sessions_is_bounded()
        {
            var sessions = Make(new TestClock(Start));

            for (var i = 0; i < AdminSessions.MaximumSessions * 3; i++)
            {
                sessions.Create("10.0.0." + i.ToString(System.Globalization.CultureInfo.InvariantCulture));
            }

            Assert.Equal(AdminSessions.MaximumSessions, sessions.Count);
        }

        // ------------------------------------------------------- form nonces

        [Fact]
        public void A_form_nonce_can_be_spent_exactly_once()
        {
            var session = Make(new TestClock(Start)).Create("10.0.0.1");
            var nonce = session.IssueNonce();

            Assert.True(session.ConsumeNonce(nonce));
            Assert.False(session.ConsumeNonce(nonce));
        }

        [Fact]
        public void A_nonce_from_nowhere_is_refused()
        {
            var session = Make(new TestClock(Start)).Create("10.0.0.1");

            session.IssueNonce();

            Assert.False(session.ConsumeNonce("invented"));
            Assert.False(session.ConsumeNonce(string.Empty));
            Assert.False(session.ConsumeNonce(null));
        }

        [Fact]
        public void Two_tabs_can_each_hold_their_own_unspent_nonce()
        {
            var session = Make(new TestClock(Start)).Create("10.0.0.1");

            var first = session.IssueNonce();
            var second = session.IssueNonce();

            Assert.True(session.ConsumeNonce(second));
            Assert.True(session.ConsumeNonce(first));
        }

        [Fact]
        public void The_number_of_unspent_nonces_is_bounded()
        {
            var session = Make(new TestClock(Start)).Create("10.0.0.1");
            var first = session.IssueNonce();

            for (var i = 0; i < AdminSession.MaximumNonces + 1; i++)
            {
                session.IssueNonce();
            }

            Assert.False(session.ConsumeNonce(first));
        }

        // -------------------------------------------------------- the flash

        [Fact]
        public void A_code_carried_in_session_state_can_be_taken_once()
        {
            var session = Make(new TestClock(Start)).Create("10.0.0.1");

            session.Flash = new AdminFlash { Code = "AAAAA-BBBBB", Tag = "0123456789ab" };

            Assert.NotNull(session.TakeFlash());
            Assert.Null(session.TakeFlash());
            Assert.Null(session.Flash);
        }
    }
}
