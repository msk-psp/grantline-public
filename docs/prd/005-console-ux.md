# PRD 005 — Console usability

## UX1 — Complete the operator workflow {#UX1}

An operator must be able to find an account or resource, inspect its access,
prepare a change, review the exact command and track its approval without losing
context. Improve the existing server-rendered console with native HTML and small
progressive enhancements; keep enforcement in the configured services.

Acceptance:

- Every screen has consistent navigation, a mobile viewport, a main landmark,
  keyboard focus indicators and a useful way back from detail and error pages.
- Inventories and the matrix can be searched, hidden account chips can be opened,
  and matrix accounts/resources link to their detail pages.
- Empty observations, unreadable scopes and an unknown account are distinct.
- Focusing a form never clears a value. Changing service retains the account and
  resets its resource/privilege fields. Required fields and service-specific
  suggestions help the operator prepare a valid preview; editing hides stale previews.
- The preview clearly separates describing, reviewing and submitting a change.
  Approval cards link to request details without exposing approval tokens.
- Successful POSTs redirect to a read-only page so refreshing does not submit the
  same change again. Invalid decisions and disabled approval routes fail clearly.
- Login changes must preserve the authentication boundary. The existing public
  application relies on an authenticated reverse proxy; the provider/integration
  choice must be established before implementing a new identity system.
- Verify desktop and narrow screens, actual browser interactions, relevant security
  boundaries and existing Python/JavaScript regressions. No production deployment.

Status: implemented and verified locally (Python 3.12 and 3.13 regression suites 24/24, lint,
JavaScript hover/API/form checks, desktop and 390 px browser checks). A mock
browser approval completed and refreshing the resulting read-only page did not
resubmit it. Native form POSTs preserve their Origin while approval URLs remain
excluded from referrers. No production or real service permission writes were used.

Authentication integration: optional trusted-proxy identity gate, sign-in entry,
account display and sign-out link. Local demo mode remains explicit and
unauthenticated. The proxy owns OIDC/session validation; Grantline stores no passwords.

Next action: review the console UX PR; configure and verify the actual proxy/SSO
provider, header stripping, network isolation and sign-out before sharing a deployment.
Live provider and production deployment validation remain pending.
