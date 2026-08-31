# One Emby account, one Authentik identity

A username is a display handle: identity providers let people change
`preferred_username`, and reassign a freed-up name to somebody else. The claim
OpenID Connect guarantees is stable and unique for a person is `sub`, so that
is what this plugin actually binds an Emby account to.

## How the binding is made and kept

- **On an account's first successful SSO sign-in**, the plugin records "this
  Authentik `sub` owns this Emby account" in
  `<Emby data path>/emby-sso/subject-bindings.json`. It is kept there and not
  in the plugin's configuration, because saving the settings page rewrites that
  file wholesale and would destroy the bindings.
- **Afterwards** a different `sub` presenting the same account name is refused,
  and so is a known `sub` presenting a different account name. The user sees the
  usual generic refusal; the server log says which it was and that an operator
  has to decide.
- **If the store cannot be read or written, sign-in fails** rather than falling
  back to matching on the username alone. An unparseable file refuses everything
  until the server is restarted and is never overwritten, so it can still be
  inspected.

## The trust-on-first-use window is real

!!! warning "Until an account has signed in once under this build, there is nothing to compare against"

    Whoever signs in first establishes the binding. The
    [group gate](groups-and-account-creation.md) and the
    [refusal to adopt unassigned accounts](before-you-install.md#a-user-with-no-provider-assigned-is-offered-to-every-enabled-provider)
    narrow that window; **they do not remove it**.

### The server log names an adoption

When an identity claims an Emby account that already existed and had no
binding — the renamed-account case below, and every account's first SSO sign-in
after this build is installed — the log says so at **Error**, naming the
account.

It is not a failure; it is the one moment a silent trust-on-first-use claim is
worth reading. An account this plugin creates itself does not produce that
line.

## Renaming an Emby account cuts both ways

!!! danger "Edit the binding store in the same maintenance window as the rename"

    The store is keyed by account *name*, so a rename does not move the row, and
    two things happen at once:

    - the person who owned the account **is refused**: their `sub` is still
      recorded against the old name, so presenting the new one is "this identity
      belongs to a different account";
    - the account under its **new** name has no row at all, so as far as the
      store is concerned it has never signed in — it is back in the
      trust-on-first-use window, and the next `sub` to present that name adopts
      it, **along with its watch history, its policy and its library access**.

What still stands in the way is the group gate and the refusal to adopt an
account that is not already assigned to this plugin — so claiming a renamed
account takes an Authentik principal that **holds the required group** and can
present the new name as its username claim. That is an in-group insider and a
narrow window, not a stranger off the internet.

It is still a window. **Stop Emby, edit that account's `account` field in
`subject-bindings.json` (or delete just that entry), and restart, as part of the
same rename — not afterwards.**

The same applies if you deliberately want to hand an account to a different
Authentik user.

!!! danger "Deleting the whole file reopens the trust-on-first-use window for every account at once"

### If you rename the Emby account but not the Authentik user

And [automatic account creation](groups-and-account-creation.md) is on: the next
sign-in matches nothing under the old name and provisions a **brand-new empty
account** under it, leaving the renamed one behind.

**Rename on both sides, in the same window.**

## The username claim must be immutable and unique in Authentik

[`preferred_username`](settings.md#username-claim) is the default and the right
answer.

If you configure `email`, the plugin refuses any token that does not assert
`email_verified` — but the underlying problem stays: many providers let a user
change their own address.
