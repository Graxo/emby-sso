using System;
using System.Globalization;
using System.IO;
using Emby.Sso.LicenceService.Configuration;

namespace Emby.Sso.LicenceService.Delivery
{
    /// <summary>
    /// The words a buyer reads at 2am, thirty seconds after paying.
    ///
    /// Plain text only, and that is a decision rather than a shortcut. A message
    /// carrying a credential someone has to retype is worse in HTML, not better:
    /// a proportional font makes 0/O and 1/l harder to tell apart, mail clients
    /// linkify and hyphenate things, and a remote image in an HTML part is a read
    /// receipt on a message containing a live secret. Plain text renders the same
    /// everywhere and copies cleanly.
    ///
    /// The wording lives in a template the operator can replace with
    /// SMTP_TEMPLATE_PATH, because the things most likely to need changing - the
    /// support address, the name of the product, where the licence box actually
    /// is in their build of the plugin - are wording, and needing a rebuilt
    /// container image to fix a typo in an email is how the typo stays.
    /// </summary>
    public static class CodeMessage
    {
        /// <summary>
        /// The placeholder a template MUST contain. A template without it would
        /// send a cheerful message with no code in it, which is worse than not
        /// sending at all, so it is refused at startup.
        /// </summary>
        public const string CodePlaceholder = "{code}";

        public const string DefaultTemplate =
@"Thank you for buying {product}.

Your licence code is:

    {code}

HOW TO USE IT

  1. In Emby, open Dashboard, then Plugins, then Emby SSO.
  2. Paste the code into the licence box on that page.
  3. Press Activate.

Your server needs to reach the licensing service once, at that moment. After
that the licence is checked on your own server, offline. The plugin does ask us
once a day whether the licence is still valid and whether there is a newer
version - you can see that task in Dashboard, Scheduled Tasks, and switch it
off. If it gets no answer, nothing changes.

WHAT IT IS WORTH

  * {licence_days} days, counted from the first time you activate it - not
    from today, so there is no hurry.
  * Up to {activations_allowed} Emby servers. Activating a server you have
    already activated - after a rebuild, a restore, or a move - does not use
    up another one.

KEEP THIS EMAIL

The code is the only copy. Anyone who has it can use it, so treat it like a
password: do not paste it into a forum, an issue tracker or a chat room.

IF IT DOES NOT WORK

Reply to this message, or write to {support}, and say exactly what the plugin
told you. Do not include the code in anything public - we can find your
purchase without it.
";

        /// <summary>
        /// Reads the operator's template, or hands back the built-in one. Called
        /// once, at startup, so that a template that would produce a codeless
        /// email is a refusal to start rather than a discovery made by the first
        /// person to pay.
        /// </summary>
        public static string LoadTemplate(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return DefaultTemplate;
            }

            string text;

            try
            {
                text = File.ReadAllText(path);
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                throw new MailTemplateException(
                    "SMTP_TEMPLATE_PATH points at '" + path + "' which could not be read: " + ex.Message, ex);
            }

            if (string.IsNullOrWhiteSpace(text))
            {
                throw new MailTemplateException("The mail template at '" + path + "' is empty.");
            }

            if (!text.Contains(CodePlaceholder, StringComparison.Ordinal))
            {
                throw new MailTemplateException(
                    "The mail template at '" + path + "' does not contain " + CodePlaceholder
                    + ", so every buyer would be emailed instructions and no code.");
            }

            return text;
        }

        /// <summary>
        /// Fills the template in. Pure: no clock, no files, no network, which is
        /// why the wording is testable without anything resembling a mail server.
        ///
        /// Returns null when there is nobody to send to. A PayPal capture does
        /// not always carry a payer email address, and inventing a recipient is
        /// not a thing to do with a bearer credential - the outbox already has
        /// the code, and the log says why nothing was sent.
        /// </summary>
        public static OutgoingMessage Build(MailOptions mail, OutboxEntry entry, string template)
        {
            if (mail == null)
            {
                throw new ArgumentNullException(nameof(mail));
            }

            if (entry == null)
            {
                throw new ArgumentNullException(nameof(entry));
            }

            if (string.IsNullOrWhiteSpace(entry.BuyerEmail))
            {
                return null;
            }

            var body = (template ?? DefaultTemplate)
                .Replace("{code}", Licensing.RedemptionCode.Format(entry.Code), StringComparison.Ordinal)
                .Replace("{licensee}", entry.Licensee ?? entry.BuyerEmail, StringComparison.Ordinal)
                .Replace("{product}", string.IsNullOrWhiteSpace(mail.ProductName) ? "the Emby SSO plugin licence" : mail.ProductName, StringComparison.Ordinal)
                .Replace("{licence_days}", entry.LicenceDays.ToString(CultureInfo.InvariantCulture), StringComparison.Ordinal)
                .Replace("{activations_allowed}", entry.ActivationsAllowed.ToString(CultureInfo.InvariantCulture), StringComparison.Ordinal)
                .Replace("{support}", Support(mail), StringComparison.Ordinal);

            return new OutgoingMessage
            {
                FromAddress = mail.FromAddress,
                FromName = mail.FromName,
                ReplyTo = mail.ReplyTo,
                ToAddress = entry.BuyerEmail.Trim(),
                Subject = string.IsNullOrWhiteSpace(mail.Subject) ? MailOptions.DefaultSubject : mail.Subject,
                Body = body,
            };
        }

        private static string Support(MailOptions mail)
        {
            return mail.SupportContact ?? mail.ReplyTo ?? mail.FromAddress ?? "the address this was sent from";
        }
    }

    /// <summary>
    /// A template that cannot produce a usable message. Thrown at startup only.
    /// </summary>
    public sealed class MailTemplateException : Exception
    {
        public MailTemplateException(string message)
            : base(message)
        {
        }

        public MailTemplateException(string message, Exception inner)
            : base(message, inner)
        {
        }
    }
}
