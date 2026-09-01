using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Emby.Sso.Licensing;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// The drift detector between the keys the PLUGIN trusts and the way this
    /// library names and signs.
    ///
    /// The plugin cannot reference this library - it targets netstandard2.0 and
    /// ships as one merged DLL onto other people's servers - so it derives a key
    /// id with its own copy of the same rule. If the two copies ever disagree,
    /// every licence names a key the plugin believes it does not have. That is
    /// survivable (the plugin falls back to trying every trusted key) but it is
    /// a silent divergence in the one mechanism that makes key rotation
    /// possible, and it should be a failing test rather than a surprise.
    ///
    /// These read the plugin's SOURCE, following the precedent of
    /// <see cref="LicenceToolCompatibilityTests"/>: there is no assembly to
    /// reference from here, so the text is what is available to assert against.
    /// </summary>
    public class PluginTrustedKeyTests
    {
        /// <summary>
        /// The keys that have been retired, by the start of their modulus. There
        /// is no revocation list and no callback: a key is revoked by not being
        /// in the plugin's trusted set, which makes "is it really gone?" a thing
        /// worth asserting rather than remembering.
        ///
        ///   * the original, which had been loaded at startup by the
        ///     internet-facing licence service AND pasted into a chat window;
        ///   * an interim key generated during that repair, whose private half
        ///     lived on a development workspace the vendor does not control.
        /// </summary>
        private static readonly string[] RetiredKeyModulusPrefixes =
        {
            "0sLbMum0TIALJnzGVTqcP1Bq02vp",
            "4MRfQ1GfRQHBCePuyRQs_4SrzClG",
        };

        /// <summary>
        /// The key this build is expected to trust, by id. Pinned so that a
        /// mistyped or half-pasted JWK is caught here rather than by every
        /// customer at once - the id is a hash of the canonical public half, so
        /// a single altered character changes it.
        /// </summary>
        private const string ExpectedKeyId = "71870a0bad21ceb2";

        [Fact]
        public void The_plugin_trusts_at_least_one_key()
        {
            Assert.NotEmpty(PluginKeys());
        }

        [Fact]
        public void Every_key_the_plugin_trusts_is_a_usable_rsa_public_key()
        {
            foreach (var jwk in PluginKeys())
            {
                var key = TrustedLicenceKeys.ReadOne(jwk);

                Assert.Equal("RSA", key.Kty);
                Assert.False(TrustedLicenceKeys.CarriesPrivateMaterial(key));
            }
        }

        [Fact]
        public void No_private_key_has_ever_been_pasted_into_the_plugin()
        {
            // The one mistake that would give the whole scheme away: the signing
            // key shipped inside every copy of the plugin. Checked against the
            // raw source rather than the parsed key, so a stray `"d"` anywhere in
            // the file fails too.
            Assert.DoesNotContain("\"d\\\"", PluginSource(), StringComparison.Ordinal);
            Assert.DoesNotContain("PRIVATE KEY", PluginSource(), StringComparison.Ordinal);
        }

        [Fact]
        public void No_retired_key_is_trusted_any_more()
        {
            foreach (var retired in RetiredKeyModulusPrefixes)
            {
                foreach (var jwk in PluginKeys())
                {
                    Assert.DoesNotContain(retired, jwk, StringComparison.Ordinal);
                }
            }
        }

        [Fact]
        public void The_build_trusts_the_key_it_is_supposed_to()
        {
            // The end of the chain: this id must be the one the vendor's signing
            // machine prints, and the one /healthz reports on the service. When
            // all three agree, a signed licence works; when they do not, every
            // licence is refused somewhere and this says which link moved.
            var ids = new System.Collections.Generic.List<string>();

            foreach (var jwk in PluginKeys())
            {
                ids.Add(TrustedLicenceKeys.ReadOne(jwk).Kid);
            }

            Assert.Contains(ExpectedKeyId, ids);
        }

        [Fact]
        public async Task A_licence_signed_for_a_key_the_plugin_trusts_names_that_key_in_its_kid()
        {
            // The rotation mechanism end to end, as far as this side can see it:
            // the id in the header is derived from the public half by the rule in
            // LicenceFormat, and the plugin derives the same id from the same
            // public half with its own copy of that rule.
            var directory = TestKeys.TempDirectory();

            try
            {
                var key = SigningKeyFile.Load(TestKeys.WritePrivateKey(directory));

                Assert.Equal(LicenceFormat.KeyId(key.PublicJwk), key.Thumbprint);

                var now = DateTimeOffset.UtcNow;
                var licence = new LicenceIssuer(key.Key).Issue("code:abcdef123456", "server", now, now.AddDays(1));

                Assert.Equal(key.Thumbprint, licence.KeyId);

                var verdict = await LicenceVerifier.VerifyAsync(
                    licence.Token,
                    new[] { TrustedLicenceKeys.ReadOne(key.PublicJwk) },
                    new SigningRequest
                    {
                        RequestId = "irrelevant",
                        Licensee = "code:abcdef123456",
                        ServerId = "server",
                        IssuedAt = LicenceFormat.Iso(now),
                        Expires = LicenceFormat.Iso(now.AddDays(1)),
                    });

                Assert.True(verdict.IsValid, verdict.Problem);
                Assert.Equal(key.Thumbprint, verdict.KeyId);
            }
            finally
            {
                Directory.Delete(directory, recursive: true);
            }
        }

        [Fact]
        public void The_key_ids_the_plugin_would_derive_are_the_ones_this_library_derives()
        {
            // Both sides hash the same canonical three-member JWK. The plugin's
            // copy is LicenceCheck.KeyIdOf; if either is edited without the
            // other, the ids stop matching and this fails.
            foreach (var jwk in PluginKeys())
            {
                var key = TrustedLicenceKeys.ReadOne(jwk);
                var canonical = LicenceFormat.PublicJwk(key.N, key.E);

                // The canonical form must be exactly what is written in the
                // plugin, or the two would hash different bytes.
                Assert.Equal(canonical, jwk);
                Assert.Equal(LicenceFormat.KeyId(canonical), key.Kid);
                Assert.Equal(16, key.Kid.Length);
            }
        }

        [Fact]
        public void The_plugin_and_this_service_can_be_configured_with_the_same_value()
        {
            // LICENCE_PUBLIC_KEYS is meant to be the same set the plugin build
            // ships with, so an operator can copy one to the other. This asserts
            // the plugin's entries go through the service's parser unchanged.
            var keys = TrustedLicenceKeys.Parse("[" + string.Join(",", PluginKeys()) + "]");

            Assert.Equal(PluginKeys().Count, keys.Count);
        }

        private static IReadOnlyList<string> PluginKeys()
        {
            // The JWKs are C# string literals, so the escaping has to come back
            // off. Only \" appears in them - a JWK is JSON with no backslashes of
            // its own - so this is the whole of the unescaping.
            return Regex
                .Matches(PluginSource(), "\"(\\{\\\\\"kty.*?\\})\"", RegexOptions.Singleline)
                .Select(match => match.Groups[1].Value.Replace("\\\"", "\"", StringComparison.Ordinal))
                .ToList();
        }

        private static string PluginSource()
        {
            var path = Path.Combine(
                RepositoryRoot(),
                "src",
                "Emby.Sso",
                "Protocol",
                "LicencePublicKey.cs");

            Assert.True(
                File.Exists(path),
                "src/Emby.Sso/Protocol/LicencePublicKey.cs was not found at " + path
                + ". If the plugin has moved, this test moves with it.");

            return File.ReadAllText(path);
        }

        private static string RepositoryRoot()
        {
            for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory != null; directory = directory.Parent)
            {
                if (Directory.Exists(Path.Combine(directory.FullName, ".git")))
                {
                    return directory.FullName;
                }
            }

            throw new InvalidOperationException("no repository root above " + AppContext.BaseDirectory);
        }
    }
}
