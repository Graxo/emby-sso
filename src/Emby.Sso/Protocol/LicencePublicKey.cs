namespace Emby.Sso.Protocol
{
    /// <summary>
    /// The vendor's licence-signing PUBLIC keys, as JWKs, compiled into the
    /// plugin. A licence is accepted if it was signed by ONE OF THESE, and by
    /// nothing else.
    ///
    /// A SET, NOT A KEY, AND THAT IS THE POINT. A build that trusts exactly one
    /// key cannot survive that key leaking: the only remedy is a new keypair and
    /// a new build, which stops every licence in the field at the same moment,
    /// including the ones belonging to customers who did nothing wrong. With a
    /// set, the new key is added and shipped while the old one is still trusted,
    /// customers are reissued at their own pace, and the old key is dropped in a
    /// later release. Rotation becomes a release rather than an outage.
    ///
    ///   * TO ROTATE: keep the entry that is here, add the new one, ship. Reissue
    ///     customers onto the new key. Delete the old entry in a later release,
    ///     once no licence signed by it is still valid.
    ///   * TO REVOKE, because a key leaked: DELETE its entry and ship
    ///     immediately. There is no revocation list and there is no callback -
    ///     the check is offline - so a key is revoked by not being here any more.
    ///     Every licence it signed stops working, which is exactly what a leaked
    ///     key requires, and is why rotating early is worth the trouble.
    ///
    /// Each licence names the key that signed it in its `kid` header, and the
    /// name is derived from the key itself (see the issuing tool's `keygen`
    /// output), so nothing has to keep a registry of which name meant which key.
    ///
    /// HOW TO ADD ONE. Run the issuing tool on a machine that is not this
    /// repository's working tree and is not a server:
    ///
    ///     dotnet run --project tools/Emby.Sso.LicenceTool -- keygen --out ~/emby-sso-licence
    ///
    /// It writes the PRIVATE key to a file and prints the PUBLIC JWK and its key
    /// id. Paste that one line into the array below and rebuild. The private key
    /// never enters this repository and never goes on a server - the licence
    /// service does not sign anything and has no key to steal. See
    /// tools/Emby.Sso.LicenceTool/README.md.
    ///
    /// AN EMPTY SET MEANS EVERY SSO SIGN-IN IS REFUSED. That is deliberate and
    /// is the fail-closed direction: a build with no key cannot verify any
    /// licence, so it cannot honestly accept one. The server log says exactly
    /// that. Emby's own local accounts are unaffected - they are authenticated
    /// by Emby's own provider, not by this plugin - so an operator is never
    /// locked out of their own server by it.
    ///
    /// These are build-time constants rather than settings on purpose. A public
    /// key an operator could edit is a public key an operator could replace with
    /// their own, and then mint their own licences.
    ///
    /// It is still, of course, only a constant inside a .NET assembly that
    /// anyone can decompile and rebuild. See <see cref="LicenceCheck"/> for what
    /// this scheme does and does not achieve.
    /// </summary>
    internal static class LicencePublicKey
    {
        /// <summary>
        /// Every key a licence may have been signed by. Order does not matter;
        /// the licence's `kid` picks one, and a licence with an unknown `kid`
        /// falls back to being tried against all of them, so a key added here
        /// works for licences issued before this build existed.
        /// </summary>
        public static readonly string[] TrustedJwks =
        {
            // Key id 173282303e3800b8. Generated 2026-09-01, when the previous
            // key was retired: that one had been on the internet-facing licence
            // service AND had been pasted into a chat window, so it had to be
            // treated as public. It is not in this array, which is what revoking
            // it means - nothing it signed validates any more, and every test
            // licence issued before that date has to be replaced.
            //
            // This key has never been on a server. Only `licencetool sign`, run
            // by hand, ever loads it.
            "{\"kty\":\"RSA\",\"n\":\"4MRfQ1GfRQHBCePuyRQs_4SrzClGhThYs4od4YOWSffORiWjQhpm0vJXtDVbRYu1d0kzE-xtCIzwM5GJJzNtyYvoldijecmwuBfM1XVEdmVZIdx38EWWxoYQVwrvTB_cC8fb1uziHes0Msu_VlGf59cJSTiqHUL8oWS-0ZA63OUv6ULclFr49pHsWJJZVaRXm2ADjnidxMkreMm30kD_0dvG8K83F197dXgDMqbXr_af9B25X1eLncgikadZDW-rjGxPLg8r2Rs5aoF-XWqZQiwToJsbLBTgSM4uBHnEjDOS-RdmtfooYdas-a1n34AuXLj2dxqOsLsG93Wc0jE0d6sDK6nNpy4K1MPcRuyqvrHSIC_sXUxEPlLMdhVBGKKZpLVYO0LAzXPelN_AErYCw21CNaVxTY3mlsx5T1O3vTaoRjG0O_ySW54PXt8hhAznWKckrf6MC0KCsAoW9K45gWZcNP4PuwLaY4dSh6mDBv2XWnDDfsXHb-jTditdyYyn\",\"e\":\"AQAB\"}",
        };
    }
}
