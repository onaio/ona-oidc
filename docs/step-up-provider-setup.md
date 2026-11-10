# Configuring an identity provider for step-up authentication

This guide is for the administrators of an OpenID Connect identity provider
that a relying party drives through this library's step-up flow. It explains
how to configure the provider so that, when the relying party asks for a
step-up, the provider demands a fresh **second factor** (a one-time code), not
just a password, and returns a token that proves the factor ran.

It covers Keycloak, WSO2 Identity Server, Azure AD B2C, and Microsoft Entra ID.
The settings named here are the provider's own; the matching relying-party
settings live in the `STEP_UP` block of the provider's entry in
`OPENID_CONNECT_AUTH_SERVERS`.

## What the library asks the provider for

On a step-up, the library sends an ordinary OIDC authorization-code request
(PKCE S256, `state`, `nonce`) with three additions:

- `max_age=0`, which asks the provider to authenticate the user again rather
  than reuse an existing session.
- `claims` requesting `auth_time` as an essential ID-token claim, because some
  providers leave `auth_time` out when `max_age` is 0.
- `acr_values=<level>`, sent only when the provider reports the assurance in
  the `acr` claim. For `prompt`-based providers the library sends `prompt`
  instead (see Azure AD B2C below).

On the callback it accepts the step-up only when both of these hold:

- the assurance claim (`acr`, `amr`, or `tfp`, depending on the provider) is
  one of the configured accepted values, and
- `auth_time` is recent (within the configured window) and not older than the
  moment the request started.

So the provider has two jobs: make the step-up request run the second-factor
step, and put a claim in the token that proves it ran. A misconfiguration
fails closed, blocking the user rather than letting anyone through.

| `STEP_UP` field | Meaning |
|---|---|
| `CLAIM` | the claim that proves the factor: `acr`, `amr`, or `tfp` |
| `SATISFIED_BY` | a list of accepted values for that claim (any-of) |
| `MAX_AGE` | sent as `max_age`; keep at `0` |
| `PROMPT` | optional; sent as `prompt` for providers that do not honour `max_age` |
| `REQUIRE_AUTH_TIME` | keep `True` so freshness is enforced |
| `REDIRECT_URI` | the step-up callback, which must be an allowed redirect URI on the provider |

A note that applies to every provider: **turn off letting a user enrol a new
factor during the step-up login.** If a user with no second factor is offered
a chance to register one mid-flow, a stolen session plus the password can
enrol an attacker-controlled factor and pass the step-up. Each section below
says how to close this.

---

## Keycloak

Keycloak supports step-up through its **Level of Authentication (LoA)**
feature. The idea: each factor sits in a conditional subflow guarded by a
level, and the request's `acr_values` selects how high to climb.

1. **Map ACR values to levels.** On the client (or realm), set the
   `acr.loa.map` attribute, for example `{"silver": 1, "gold": 2}`.

2. **Build a browser flow with one conditional level per factor.** Copy the
   built-in `browser` flow and edit the copy so that:
   - A conditional subflow guarded by **Condition - Level of Authentication**
     at level 1 contains the **Username Password Form**.
   - A conditional subflow guarded by **Condition - Level of Authentication**
     at level 2 contains the **OTP Form**.
   - The copied **Conditional OTP** subflow is **disabled**. Left on, it runs
     the OTP step for anyone who holds an OTP credential on every login, so a
     plain sign-in would also ask for a code.

   Keeping the password inside its own level matters: with the password
   outside any level, level 1 does not exist, and a request that asks for no
   `acr_values` resolves to the highest level and prompts for the code every
   time.

3. **Bind the flow** as the realm's browser flow, or override it on the
   client.

Result: a plain login resolves to the lowest level and asks for the password
only; a request carrying `acr_values=gold` climbs to level 2 and runs the OTP
form. The token then carries `acr=gold`.

Relying-party settings: `CLAIM="acr"`, `SATISFIED_BY=["gold"]`. The library
sends `acr_values=gold` automatically because the claim is `acr`.

**Close the enrolment gap:** in the OTP flow, a user without an authenticator
is shown a QR code to configure one. Require OTP to be configured out of band
(for example through the account console) rather than during this flow, or the
step-up can be satisfied by enrolling a fresh factor on the spot.

---

## WSO2 Identity Server

WSO2 reports the factor in the `amr` claim (a list of the authenticator names
that ran, such as `totp`, `email-otp-authenticator`, `sms-otp-authenticator`),
and reports `acr` only when an adaptive script sets it. Choose one of two
shapes.

**Option A, every login asks for the factor.** Build the application's login
flow as two steps:

1. Username and password.
2. One or more second-factor authenticators (TOTP, Email OTP, SMS OTP).

There must be no conditional script that skips step 2 for some users, devices
or sessions. Relying-party settings: `CLAIM="amr"`, `SATISFIED_BY=["totp"]`
(or the exact authenticator names that count as a second factor; never the
password authenticator).

**Option B, the factor only when the relying party asks.** Keep the two steps
and add an adaptive authentication script that runs step 2 only for the higher
ACR:

```js
var supportedAcrValues = ['silver', 'gold'];

var onLoginRequest = function (context) {
    var selectedAcr = selectAcrFrom(context, supportedAcrValues) || 'silver';
    context.selectedAcr = selectedAcr;
    executeStep(1);
    if (selectedAcr === 'gold') {
        executeStep(2);
    }
};
```

The script must run step 2 whenever `gold` is selected and must never set
`gold` otherwise. A normal sign-in returns `silver` and is unaffected.
Relying-party settings: `CLAIM="acr"`, `SATISFIED_BY=["gold"]`.

**`auth_time` on `max_age=0`:** WSO2 leaves `auth_time` out of the token for
`max_age=0` unless it is requested as an essential claim. The library always
requests it, so no extra provider setting is needed, but confirm `auth_time`
appears in an issued token. (If you run a relying party that does not request
it, `MAX_AGE: 1` is the workaround, at the cost of the deploy warning about a
non-zero max age.)

**Close the enrolment gap:** WSO2's default lets a user with no TOTP
authenticator scan a new QR code during login, and the token then reports
`totp`. Turn off progressive enrolment. On Identity Server 7.x this is the
per-organisation setting **Enable TOTP Device Progressive Enrollment**
(`TOTP.EnrolUserInAuthenticationFlow`); on 5.x and 6.x it is
`enrolUserInAuthenticationFlow` in `deployment.toml`. Also confirm no adaptive
script passes `enrolUserInAuthenticationFlow: true` to the authenticator,
which overrides both. Do the same for any other step-2 authenticator that
offers enrolment during login.

---

## Azure AD B2C

B2C puts the **user-flow name** in the token (in the `tfp` claim, or `acr`
depending on the flow's token setting), not a statement that MFA ran. A flow
with conditional MFA returns the same name whether the second factor was asked
for or not. So step-up needs a flow whose name can only be issued after MFA.

1. **Create a dedicated sign-in user flow** with multifactor authentication
   set to **Always on** (not Conditional, not Off). Give it the same identity
   providers and the same returned claims (at least the email address) as your
   normal sign-in flow.

2. **Confirm the token settings:** the issuer format matches your sign-in
   flow, and note whether the flow puts its name in `tfp` or `acr`.

Relying-party settings: `CLAIM="tfp"` (or `acr`), and `SATISFIED_BY` set to the
exact flow name as it appears in a real token (B2C lowercases flow names in its
discovery document, so copy the value from a decoded token).

**Forcing a fresh factor:** B2C has no documented `max_age`. The documented
lever is `prompt=login`, so set `PROMPT: "login"`. Note that `prompt=login` in
B2C forces a full re-authentication and bypasses single sign-on; MFA-only
re-authentication is not available.

**`auth_time`:** confirm the flow emits `auth_time`. If it does not, either
keep `REQUIRE_AUTH_TIME: True` only after confirming the claim is present, or
accept that the freshness check cannot run and rely on `prompt=login` having
forced a fresh sign-in.

**Close the enrolment gap:** with phone or authenticator-app MFA, B2C offers a
user with no registered method the chance to register one during the flow. A
user flow has no switch to prevent this. Close it another way: ensure every
active user already registered a method, use email as the method (the code
goes to the account's verified address), or use a custom policy that refuses
users with no registered method.

---

## Microsoft Entra ID (workforce)

Entra ID uses a different model from the three providers above, and the
difference matters.

**The mechanism.** Entra ID does not drive step-up with `acr_values` or a
single `acr` value. It uses **Conditional Access authentication contexts**:

1. Define an authentication context, for example `c1`.
2. Bind a Conditional Access policy that requires MFA to that context.
3. The application asks for the context through the OIDC `claims` request
   parameter, requesting that the `acrs` claim contain `c1`.
4. Satisfied contexts come back in the **`acrs` claim**, which is an array. If
   the required context is absent, Entra raises a claims challenge, which the
   application intercepts and sends back to Entra for further evaluation. The
   `xms_cc` claim (value `cp1`) signals that the client can handle a claims
   challenge.

**Support status.** This library's step-up request sends `acr_values` (only
when `CLAIM` is `acr`) and reads a single assurance claim against
`SATISFIED_BY`. It does **not** emit the `claims={"id_token":{"acrs":{...}}}`
request that Entra ID needs, and it does not treat the `acrs` array as the
assurance signal. So Entra ID step-up is **not supported by the current request
flow without a library change**. Supporting it would mean emitting the `acrs`
claims request and reading the `acrs` array (checking membership, since it can
hold several context IDs) rather than a single claim value. It is documented
here so the mechanism and the required work are on record.

References: Microsoft's developer guidance for Conditional Access
authentication context,
<https://learn.microsoft.com/en-us/entra/identity-platform/developer-guide-conditional-access-authentication-context>,
and the optional claims reference,
<https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims-reference>.

---

## Verifying the setup

Before and after configuring, fetch the provider's discovery document and
confirm the endpoints and that the assurance claim is advertised:

```
curl -s https://<provider-host>/.well-known/openid-configuration \
  | jq '{authorization_endpoint, token_endpoint, claims_supported}'
```

`claims_supported` listing a claim is necessary but not sufficient. The real
test is to complete one step-up and decode the ID token: confirm it carries
the expected `CLAIM` value and a fresh `auth_time`. A test user with no second
factor must not be able to complete the step-up.

## Deploy checks

Two startup checks guard the relying-party side:

- `oidc.W001` warns when `STEP_UP["MAX_AGE"]` is not 0.
- `oidc.W002` warns when the step-up cache is per-process (such as local
  memory), which cannot hold single-use state across workers.
