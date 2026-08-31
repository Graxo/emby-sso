using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Logging;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// Keeps every line a class logged, formatted exactly as a console provider
    /// would format it, so a test can assert what is NOT in it.
    ///
    /// That is the point of this class. "The redemption code is never logged" and
    /// "the SMTP password is never logged" are properties of the service that no
    /// amount of reading the source proves for long, because the next person to
    /// add a log line will not have read it. Asserting over the rendered text -
    /// message, arguments, exception and all - catches it.
    /// </summary>
    internal sealed class RecordingLogger<T> : ILogger<T>
    {
        private readonly List<Line> _lines = new List<Line>();

        public IReadOnlyList<Line> Lines => _lines;

        /// <summary>Every line rendered end to end, including exception text.</summary>
        public string Everything => string.Join("\n", _lines.Select(l => l.Rendered));

        public IEnumerable<Line> At(LogLevel level) => _lines.Where(l => l.Level == level);

        public IDisposable BeginScope<TState>(TState state) where TState : notnull => new Nothing();

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception exception,
            Func<TState, Exception, string> formatter)
        {
            var text = formatter(state, exception);

            if (exception != null)
            {
                // Including the exception, because "the code is not in the log"
                // has to hold for the disaster paths too, and an exception message
                // is the easiest place for a secret to escape into.
                text += " || " + exception;
            }

            _lines.Add(new Line(logLevel, text));
        }

        internal sealed class Line
        {
            public Line(LogLevel level, string rendered)
            {
                Level = level;
                Rendered = rendered;
            }

            public LogLevel Level { get; }

            public string Rendered { get; }
        }

        private sealed class Nothing : IDisposable
        {
            public void Dispose()
            {
            }
        }
    }
}
