using System;

namespace Emby.Sso.Tests
{
    public sealed class TestClock
    {
        public DateTimeOffset Now { get; set; } = new DateTimeOffset(2026, 8, 30, 12, 0, 0, TimeSpan.Zero);

        public Func<DateTimeOffset> Func => () => Now;

        public void Advance(TimeSpan by) => Now = Now.Add(by);
    }
}
