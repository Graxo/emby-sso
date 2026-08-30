using System;
using System.Text;

namespace Emby.Sso.Protocol
{
    /// <summary>
    /// Flattens an untrusted string for safe inclusion in a single log line:
    /// strips control characters (including CR and LF) and caps the length, so
    /// a provider- or attacker-supplied string can never forge additional log
    /// lines or grow a log entry without bound. Shared by every layer that logs
    /// a value it did not itself produce - the Protocol layer's OAuth error
    /// codes and the Api layer's callback query parameters alike.
    /// </summary>
    public static class LogSafeText
    {
        public const int MaxLength = 200;

        public static string Flatten(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return string.Empty;
            }

            var builder = new StringBuilder(Math.Min(value.Length, MaxLength));

            foreach (var character in value)
            {
                if (builder.Length >= MaxLength)
                {
                    break;
                }

                builder.Append(char.IsControl(character) ? ' ' : character);
            }

            return builder.ToString();
        }
    }
}
