namespace Emby.Sso.Protocol
{
    /// <summary>
    /// The vendor's licence-signing PUBLIC key, as a JWK, compiled into the
    /// plugin.
    ///
    /// HOW TO FILL THIS IN. Run the issuing tool once, on a machine that is not
    /// this repository's working tree:
    ///
    ///     dotnet run --project tools/Emby.Sso.LicenceTool -- keygen --out ~/emby-sso-licence
    ///
    /// It writes the PRIVATE key to a file and prints the PUBLIC JWK. Paste that
    /// one line between the quotes below and rebuild. The private key never
    /// enters this repository - see tools/Emby.Sso.LicenceTool/README.md for
    /// where it should live instead.
    ///
    /// EMPTY MEANS EVERY SSO SIGN-IN IS REFUSED. That is deliberate and is the
    /// fail-closed direction: a build with no key cannot verify any licence, so
    /// it cannot honestly accept one. The server log says exactly that. Emby's
    /// own local accounts are unaffected - they are authenticated by Emby's own
    /// provider, not by this plugin - so an operator is never locked out of
    /// their own server by it.
    ///
    /// This is a build-time constant rather than a setting on purpose. A public
    /// key an operator could edit is a public key an operator could replace with
    /// their own, and then mint their own licences.
    ///
    /// It is still, of course, only a constant inside a .NET assembly that
    /// anyone can decompile and rebuild. See <see cref="LicenceCheck"/> for what
    /// this scheme does and does not achieve.
    /// </summary>
    internal static class LicencePublicKey
    {
        public const string Jwk = "{\"kty\":\"RSA\",\"n\":\"0sLbMum0TIALJnzGVTqcP1Bq02vp4xHvFJpBR7a5tRMnvBiLqwYrfptdpFLX9uVMoYtg_HYt0Es8Y1-UE5hTDciJ-AlyTuN9lPV5snaipWTXhSA2nLRk_fT5XXAe9yFN17fDzU1Iexl4dSrYPgRey8L_XmVgS7opGBlyfI42z8v8YaurYa1c05kbbriGAKvBjVywJYrMAG2gFj0Z5aOZm8q9ibVTiNltfw8GKDoDNtHq-jIAVAavoWo3tQRu_IuTDJI18Zy9mTiqfTwFxOqVlxQYUxnGXpvUZfgI_HsjjlWvX89W7Tr69-uBjUBMqjCUdnyJtJQvdrM_c3HeQax0FIr2r4MJVrVa-N4V3rEfIIMrDFlPy_c2X8wfSRSKlODSCtlJz2hYcQ5-pR_SNYBvGjBpmMJXnK6jQq1mfj9BNmG5JJgO1c5H-QVB5d4NIJLjsuWUiQr_Q_0rsPI29BpoXbRdMeI0L34qreSsfvvhvgXh8pAY77feKGFoX8-t6n07\",\"e\":\"AQAB\"}";
    }
}
