using System;
using System.Globalization;
using System.Net;
using System.Text;

namespace Emby.Sso.LicenceService.Http
{
    /// <summary>
    /// The one page a human sees: GET /buy, opened from the "Buy a licence" link
    /// on the plugin's configuration page in somebody's Emby dashboard.
    ///
    /// It is a page with a button rather than an immediate redirect into a
    /// created PayPal order, and that is a deliberate choice:
    ///
    ///   * A GET that creates a PayPal order as a side effect gets fired by every
    ///     link prefetcher, every crawler, every dashboard reload and every
    ///     browser that speculatively loads a link on hover. Each one would be an
    ///     authenticated call against the vendor's PayPal account, against a
    ///     rate-limited API, for a sale nobody asked to start.
    ///   * The buyer should see the price, the term and the number of servers
    ///     BEFORE they are handed to PayPal. A redirect shows them a payment
    ///     screen for an amount they have not been told.
    ///
    /// The button is a plain form POST to /buy/start, which creates the order and
    /// answers 303 to PayPal's approval URL. No JavaScript: this page is served
    /// to whatever browser an Emby administrator happens to have, and a checkout
    /// that fails silently because a script did not run is a lost sale that
    /// leaves no trace.
    ///
    /// EVERYTHING INTERPOLATED HERE IS HTML-ENCODED. The server id arrives in a
    /// query parameter that anybody can set, and is echoed back to the page; a
    /// reflected-XSS hole on the page that starts a payment would be a
    /// remarkable way to begin selling something.
    /// </summary>
    internal static class BuyPage
    {
        public static string Render(BuyPageModel model)
        {
            if (model == null)
            {
                throw new ArgumentNullException(nameof(model));
            }

            var page = new StringBuilder();

            page.Append("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">");
            page.Append("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
            page.Append("<title>").Append(Escape(model.ProductName)).Append("</title>");
            page.Append("<style>");
            page.Append("body{font:16px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;");
            page.Append("margin:0;padding:2.5rem 1.25rem;background:#f6f7f9;color:#16191d;}");
            page.Append("main{max-width:34rem;margin:0 auto;background:#fff;border:1px solid #dfe3e8;");
            page.Append("border-radius:10px;padding:1.75rem;}");
            page.Append("h1{font-size:1.4rem;margin:0 0 .25rem;}");
            page.Append("p{margin:.75rem 0;}");
            page.Append(".price{font-size:2rem;font-weight:600;margin:.5rem 0 1rem;}");
            page.Append("ul{margin:.5rem 0 1.25rem 1.1rem;padding:0;}");
            page.Append("li{margin:.3rem 0;}");
            page.Append("button{font:inherit;font-weight:600;background:#ffc439;border:1px solid #e0a800;");
            page.Append("color:#16191d;border-radius:6px;padding:.7rem 1.4rem;cursor:pointer;}");
            page.Append(".muted{color:#5b6672;font-size:.9rem;}");
            page.Append(".notice{background:#fdf6e3;border:1px solid #f0dfa8;border-radius:6px;padding:.75rem 1rem;}");
            page.Append("</style></head><body><main>");

            page.Append("<h1>").Append(Escape(model.ProductName)).Append("</h1>");

            if (!model.CanSell)
            {
                // Said plainly rather than shown as a broken button. An operator
                // who has not finished configuring PayPal should see why, and a
                // customer should not be given a button that cannot work.
                page.Append("<p class=\"notice\">This service is not set up to take payments yet. ");
                page.Append("Please contact the vendor for a licence.</p>");
                page.Append(Footer(model));
                page.Append("</main></body></html>");

                return page.ToString();
            }

            page.Append("<p class=\"price\">")
                .Append(Escape(model.Price))
                .Append(' ')
                .Append(Escape(model.Currency))
                .Append("</p>");

            page.Append("<ul>");
            page.Append("<li>A licence valid for <strong>")
                .Append(model.LicenceDays.ToString(CultureInfo.InvariantCulture))
                .Append(" days</strong> from the day you activate it.</li>");
            page.Append("<li>Usable on up to <strong>")
                .Append(model.ActivationsAllowed.ToString(CultureInfo.InvariantCulture))
                .Append(" Emby servers</strong>. Re-activating a server you have already used is free.</li>");
            page.Append("<li>You get a redemption code, which you paste into the plugin's settings.</li>");
            page.Append("</ul>");

            page.Append("<form method=\"post\" action=\"/buy/start\">");

            if (model.ServerId != null)
            {
                page.Append("<input type=\"hidden\" name=\"serverId\" value=\"")
                    .Append(Escape(model.ServerId))
                    .Append("\">");
            }

            page.Append("<button type=\"submit\">Pay with PayPal</button>");
            page.Append("</form>");

            page.Append("<p class=\"muted\">Your redemption code is sent to the email address on your PayPal payment. ");
            page.Append("It does not depend on this page staying open - you can close the tab as soon as PayPal says ");
            page.Append("the payment went through.</p>");

            page.Append(Footer(model));
            page.Append("</main></body></html>");

            return page.ToString();
        }

        public static string RenderComplete(BuyPageModel model)
        {
            var page = new StringBuilder();

            page.Append("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">");
            page.Append("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
            page.Append("<title>Thank you</title>");
            page.Append("<style>body{font:16px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;");
            page.Append("margin:0;padding:2.5rem 1.25rem;background:#f6f7f9;color:#16191d;}");
            page.Append("main{max-width:34rem;margin:0 auto;background:#fff;border:1px solid #dfe3e8;");
            page.Append("border-radius:10px;padding:1.75rem;}h1{font-size:1.4rem;margin:0 0 .5rem;}");
            page.Append(".muted{color:#5b6672;font-size:.9rem;}</style></head><body><main>");
            page.Append("<h1>Thank you - your payment has been received.</h1>");

            // NO CODE IS EVER SHOWN HERE, and the page says what happens instead.
            // Three reasons, in order of weight: PayPal's webhook is what creates
            // the code and it may not have arrived yet, so this page would often
            // have nothing true to say; a redemption code is a live credential and
            // this URL carries a PayPal order id that lands in browser history,
            // proxy logs and Referer headers; and a delivery that only works if
            // the buyer keeps a tab open is a delivery that fails for the people
            // least able to chase it.
            page.Append("<p>Your redemption code goes to the email address on your PayPal payment. ");
            page.Append("It is not shown here on purpose - a licence code is a credential, and this page's ");
            page.Append("address ends up in your browser history.</p>");
            page.Append("<p>Nothing depends on this tab. Closing it now loses nothing: the code was created when ");
            page.Append("PayPal confirmed the payment, not when this page loaded.</p>");
            page.Append("<p class=\"muted\">If it has not arrived within a working day, reply to your PayPal receipt ");
            page.Append("or contact the vendor with the transaction id from it - that is enough to find your code.</p>");
            page.Append(Footer(model));
            page.Append("</main></body></html>");

            return page.ToString();
        }

        /// <summary>
        /// PayPal would not create the order. The buyer is told plainly and told
        /// that nothing was charged, because the alternative - a blank page or a
        /// stack trace - reads as "I have just paid and something went wrong".
        /// </summary>
        public static string RenderFailed(BuyPageModel model)
        {
            var page = new StringBuilder();

            page.Append("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">");
            page.Append("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
            page.Append("<title>Could not start checkout</title>");
            page.Append("<style>body{font:16px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;");
            page.Append("margin:0;padding:2.5rem 1.25rem;background:#f6f7f9;color:#16191d;}");
            page.Append("main{max-width:34rem;margin:0 auto;background:#fff;border:1px solid #dfe3e8;");
            page.Append("border-radius:10px;padding:1.75rem;}h1{font-size:1.4rem;margin:0 0 .5rem;}</style>");
            page.Append("</head><body><main>");
            page.Append("<h1>Could not start the payment.</h1>");
            page.Append("<p><strong>Nothing was charged.</strong> PayPal did not accept the request to start a ");
            page.Append("checkout. This is a problem at the vendor's end, not yours.</p>");
            page.Append("<p><a href=\"/buy\">Try again</a> in a few minutes, or contact the vendor if it keeps ");
            page.Append("happening.</p>");
            page.Append(Footer(model));
            page.Append("</main></body></html>");

            return page.ToString();
        }

        public static string RenderCancelled(BuyPageModel model)
        {
            var page = new StringBuilder();

            page.Append("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">");
            page.Append("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
            page.Append("<title>Payment cancelled</title>");
            page.Append("<style>body{font:16px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;");
            page.Append("margin:0;padding:2.5rem 1.25rem;background:#f6f7f9;color:#16191d;}");
            page.Append("main{max-width:34rem;margin:0 auto;background:#fff;border:1px solid #dfe3e8;");
            page.Append("border-radius:10px;padding:1.75rem;}h1{font-size:1.4rem;margin:0 0 .5rem;}</style>");
            page.Append("</head><body><main>");
            page.Append("<h1>Payment cancelled.</h1>");
            page.Append("<p>Nothing was charged and no licence was created. ");
            page.Append("<a href=\"/buy\">Start again</a> whenever you like.</p>");
            page.Append(Footer(model));
            page.Append("</main></body></html>");

            return page.ToString();
        }

        private static string Footer(BuyPageModel model)
        {
            if (model.ServerId == null)
            {
                return string.Empty;
            }

            // Echoed back so the administrator can see the link carried their
            // server id, and so a support conversation has something to match on.
            // It is NOT what the licence gets bound to: a code is server-agnostic
            // until it is activated, and it is the activation that names a server.
            return "<p class=\"muted\">Started from Emby server <code>"
                + Escape(model.ServerId)
                + "</code>. Your licence is not tied to it yet - the server you activate the code on is the one it "
                + "binds to.</p>";
        }

        private static string Escape(string value)
        {
            return WebUtility.HtmlEncode(value ?? string.Empty);
        }
    }

    internal sealed class BuyPageModel
    {
        public string ProductName { get; set; }

        public string Price { get; set; }

        public string Currency { get; set; }

        public int LicenceDays { get; set; }

        public int ActivationsAllowed { get; set; }

        /// <summary>
        /// The server id from the query string, already validated and truncated,
        /// or null if there was none or it was not plausible. Untrusted either
        /// way: it is HTML-encoded everywhere it is rendered.
        /// </summary>
        public string ServerId { get; set; }

        public bool CanSell { get; set; }
    }
}
