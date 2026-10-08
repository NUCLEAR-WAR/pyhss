# PyHSS Cx registration patch

This package contains replacement and new files for the supplied PyHSS source,
with repository-relative paths. Extract its contents into your fork's root and
upload the files in their existing folders. Install the updated requirements
and restart the PyHSS services. Your existing native subscriber and AuC records
remain the source of credentials; Cx uses the configured PyHSS SQLAlchemy engine.
The supplied archive's native UDR/PCF model additions are retained.

Alternatively, apply `pyhss-cx-lab-debug.patch` from the original supplied PyHSS
fork, or `pyhss-cx-lab-debug-update.patch` if the previous repo-ready package is
already applied:

```sh
git apply --check /path/to/pyhss-cx-lab-debug.patch
git apply /path/to/pyhss-cx-lab-debug.patch
python -m pip install -r requirements.txt
```

The full patch is checked against `pyhss-master (1).zip`, and the update patch
against the previous `pyhss-cx-repo-ready.zip` package. If your fork
has additional changes in these files, review the diff before replacing them.
This changes-only package is intended for that PyHSS fork, rather than the
separate merged IMS lab whose database extension differs.

Subscriber identities, secrets and authentication policies come from the native
database and explicitly provisioned profiles. The operator's `hss.OriginHost`,
`hss.OriginRealm`, `hss.MCC` and `hss.MNC` come from configuration. Keep MCC and
MNC as quoted digit strings to preserve leading zeroes. MCC must contain three
digits and MNC two or three. Missing values fail instead of selecting a default
network. Standard Diameter identifiers, result codes and algorithm constants
remain in the code because the protocol defines them.

## Provision identities before registration

UAR, MAR and SAR never create an IMPI/IMPU association from a request. For a
fixed subscriber whose authentication username differs from the native IMSI,
explicitly associate the full private and public identities with its existing
IMS subscription before registering. Existing native IMSIs are not rewritten.
Legacy IFC profiles remain a read-only source of pre-provisioned identities.

Create your own profile JSON with these fields:

| Field | Value to supply |
|---|---|
| `private_identities` | List of exact full private identities, including the home realm |
| `public_identities` | List of objects with `identity`, `set_id` and `barred` |
| `authentication_scheme` | Default provisioned scheme: `SIP Digest` or `Digest-AKAv1-MD5` |
| `authentication_schemes` | Optional map from full private identity to a scheme or an explicit list of allowed schemes |
| `digest_realm` | The provisioned authentication realm |
| `visited_networks` | List of permitted visited network identifiers |
| `unregistered_service` | Boolean indicating provisioned unregistered service policy |

Use a shared `set_id` for public identities in the same implicit registration
set. An optional public identity's `private_identities` list restricts its
association to provisioned private identities. Every identity in an implicit
registration set must have the same private associations. No subscriber-specific
profile is included in this package.

Run the provisioning tool with the same `PYHSS_CONFIG` as your running HSS.
The variables below must contain your actual configuration path, existing IMS
subscriber database ID and profile path:

```sh
PYHSS_CONFIG="$HSS_CONFIG_PATH" python tools/provision_cx_profile.py \
  --ims-subscriber-id "$IMS_SUBSCRIBER_ID" --profile "$CX_PROFILE_PATH"
```

The tool also accepts `--msisdn` instead of `--ims-subscriber-id`. It matches an
existing IMS row; it does not create a subscriber or assign an S-CSCF.
Replacing an existing profile requires explicit `--replace` after de-registration.
Startup creates three additive `ims_cx_*` tables through the native database
engine. Provisioning and runtime changes use transactions, including SQN updates.

## Registration behavior

| Procedure | Expected behavior |
|---|---|
| First UAR without an assignment | Experimental FIRST_REGISTRATION; no identity or runtime writes |
| MAR | Authenticate using the linked native AuC, select S-CSCF and mark authentication pending |
| UAR after MAR | Experimental SUBSEQUENT_REGISTRATION with the assigned S-CSCF |
| SAR REGISTRATION | Mark registration successful, clear pending and return subscription data |
| UAR DE_REGISTRATION | Read-only query; preserve state until SAR |
| SAR de-registration | Update the relevant registration and clear routing when no longer needed |

A second UAR after MAR may correctly be SUBSEQUENT_REGISTRATION during the same
SIP registration exchange. Authentication pending is distinct from successful
registration. A legacy S-CSCF value without a registration timestamp is not
treated as evidence of an assignment; timestamped legacy registrations are retained.

Fixed MAA uses standard `SIP Digest` and grouped SIP-Digest-Authenticate with
HA1 calculated from the full IMPI, realm and provisioned secret. No plaintext
password is returned. AKA uses actual Milenage vectors; authenticated AUTS is
verified before SQN changes. UAR/LIR remain read-only, and native administrative
de-registration clears corresponding Cx state. Outbound RTR uses the provisioned
private identity and assigned destination.

The S-CSCF must request `SIP Digest` for fixed authentication. In Kamailio
`ims_auth`, the challenge argument `3GPP-Digest` selects that Cx scheme.
A peer requesting legacy `Digest-MD5` is rejected by default. If an operator
explicitly sets `hss.cx.accept_legacy_digest_md5: true`, that request alias is
accepted but MAA still emits standard SIP Digest with HA1.

Authentication policy is provisioned per private identity. A mobile identity can
retain `Digest-AKAv1-MD5` while a fixed alias on the same native IMS subscription
uses `SIP Digest`. An explicit list may allow both for a lab identity. Neither
request handlers nor username length, number format or User-Agent add a scheme.
For `Unknown` (also accepting Kamailio's lowercase spelling), the HSS selects
SIP Digest only when it is explicitly allowed. An AKA-only profile returns 5006
for that request, as required by TS 29.228 section 6.3.1. A real mobile S-CSCF
must therefore request `Digest-AKAv1-MD5` explicitly on this strict implementation.

The accompanying IMS S-CSCF patch fixes the original unconditional MD5 fallback.
It uses the configured AKA default for mobile initial registration and standard
3GPP-Digest for the dedicated fixed P-CSCF Path. An explicit client AKA algorithm
is preserved; an IPsec-3GPP Security-Client offer uses the mobile default even on
that fixed ingress. The fixed Path pattern is an operator configuration entry
derived from the lab's IMS domain, with no embedded subscriber or site address.

Set `hss.cx.server_capabilities` to the operator's actual `mandatory` and
`optional` capability lists when capability-based S-CSCF selection is used.
No capability IDs or S-CSCF endpoints are invented by the new Cx handlers.

## Lab MySQL without TLS and diagnosing USER_UNKNOWN

To explicitly disable TLS for PyHSS's MySQL/MariaDB connection, add this key
inside the existing `database` section of the actual runtime PyHSS configuration:

```yaml
database:
  ssl_disabled: true
```

Keep your existing database type, server, database name, username and password
in that same section. Restart all PyHSS processes after changing the setting.
This forwards `ssl_disabled=True` to PyMySQL. Omitting it leaves the driver's
default policy in place; `false` does not require encryption. SQLite and
PostgreSQL are unaffected by this MySQL-specific option. If the server or
database account requires TLS, it must also permit this lab connection without
TLS. This flag does not change the server's policy or Diameter/SIP transport.

If your Compose startup generates the configuration, edit the generating
template too. For the previously supplied merged lab, add the boolean to the
`database` section in `docker/config.yaml` and recreate the PyHSS containers.
For a source build, rebuild the PyHSS image to include these updated files.

Run diagnostics inside the PyHSS environment with the same configuration:

```sh
PYHSS_CONFIG="$HSS_CONFIG_PATH" python tools/diagnose_cx.py \
  --private-identity "$IMPI" --public-identity "$IMPU" --ifc-report
```

For an existing container, set `PYHSS_CONTAINER` and `PYHSS_ROOT` to its actual
name and PyHSS source path, then run:

```sh
docker exec -w "$PYHSS_ROOT" "$PYHSS_CONTAINER" python tools/diagnose_cx.py \
  --private-identity "$IMPI" --public-identity "$IMPU" --ifc-report
```

Supply the exact User-Name and Public-Identity from the failing UAR, including
their realms and public URI scheme. If the container needs an explicit config
path, pass `-e PYHSS_CONFIG="$HSS_CONFIG_PATH"` before its container name.

The tool opens a connection with the same native connector settings, queries
its session `Ssl_cipher` and checks both identities independently, their
association, native subscriber/AuC links and legacy IFC validity. It creates
no tables, provisions no identities and changes no registration or SQN. Output
contains no Ki, OPc, passwords or connection URLs. `mysql_connection_encrypted`
must be `false` with an empty `mysql_tls_cipher` for plaintext transport.
The check verifies a new connection using the same settings; restart the live
workers so existing pooled connections also use the changed policy.

The live HSS also logs explicit lookup reasons such as
`public_identity_not_provisioned`, `private_identity_not_provisioned` or
`native_auc_not_found`, without including authentication secrets.
Experimental 3GPP 5001 is USER_UNKNOWN. Backend exceptions in these patched
handlers return base 5012. A SQLAlchemy `ROLLBACK` after a read is normal, and
`cached since` indicates reuse of compiled SQL rather than cached subscriber data.

If the public identity is missing, provision the exact static identity profile
using `tools/provision_cx_profile.py` before registration. An existing MSISDN row
alone does not provision every possible full IMPI/IMPU. If the same subscription
already has an explicit profile, inspect and preserve its other identities when
replacing it. This is operator provisioning, never learning a binding from UAR.
Disabling MySQL encryption does not resolve a missing identity.

For a simple fixed SIP Digest profile, the CLI can provision explicit values
without creating a JSON file. Set `IMPI`, `IMPU`, `VISITED_NETWORK` and
`IMS_SUBSCRIBER_ID` to the operator-approved values first:

```sh
docker exec -w "$PYHSS_ROOT" "$PYHSS_CONTAINER" python tools/provision_cx_profile.py \
  --ims-subscriber-id "$IMS_SUBSCRIBER_ID" \
  --private-identity "$IMPI" --public-identity "$IMPU" \
  --authentication-scheme 'SIP Digest' --visited-network "$VISITED_NETWORK" \
  --set-id fixed --preserve-existing
```

Repeat `--private-identity`, `--public-identity` or `--visited-network` to provision
additional explicit entries. Use `--profile` JSON for barred identities or more
complex implicit sets. The inline options and `--profile` are mutually exclusive.
This command does not assign an S-CSCF. A fresh initial UAR remains
FIRST_REGISTRATION because provisioning creates no runtime registration state.
The fixed client's password must match the native AuC secret used for SIP Digest.
Keep its authentication username equal to the full provisioned private identity.

`--preserve-existing` reads the pre-provisioned legacy/explicit profile at operator
provisioning time and retains its identities, sets and authentication policies.
It does not run during UAR. Use a distinct `--set-id` for a new fixed alias so
the existing mobile registration set remains intact. Replacing a profile already
stored in `ims_cx_profile` still requires `--replace` after de-registration.

For a softphone using the *same* IMSI private identity as a SIM, explicitly allow
SIP Digest in addition to existing AKA. This preserves AKA rather than replacing
it. Supply that existing full private/public identity and its visited network:

```sh
docker exec -w "$PYHSS_ROOT" "$PYHSS_CONTAINER" python tools/provision_cx_profile.py \
  --ims-subscriber-id "$IMS_SUBSCRIBER_ID" \
  --private-identity "$IMPI" --public-identity "$IMPU" \
  --authentication-scheme 'SIP Digest' --visited-network "$VISITED_NETWORK" \
  --preserve-existing --allow-additional-scheme
```

The existing scheme is retained. Without `--allow-additional-scheme`, adding a
different scheme to an existing private identity is rejected. Allowing both is
an explicit lab provisioning policy; it does not silently allow Digest-MD5.

## Reference capture comparison

The supplied successful production capture uses MAR `Unknown`, followed by MAA
`SIP Digest` with grouped Digest-Realm/Algorithm/QoP/HA1, then subsequent UAR 2002
and successful SAR. Its LDAP backend stores subscriber data; PyHSS performs those
lookups through its configured native database. The backend choice does not
change the Diameter authentication scheme.

The supplied original real-mobile capture uses lowercase `unknown` followed by
MAA `Digest-AKAv1-MD5`, with RAND/AUTN, XRES, CK and IK. The old HSS accepted that
scheme fallback. The strict patch retains those AKA vectors and successful SAR
while correcting the S-CSCF's MAR request to explicit AKA. It does not copy the
old fallback or its first-UAR prefilled Server-Name behavior as normative rules.

From the original IMS lab root, apply `ims-scscf-mobile-fixed-auth.patch` and
recreate the S-CSCF so its startup copies the changed configuration:

```sh
git apply --check /path/to/ims-scscf-mobile-fixed-auth.patch
git apply /path/to/ims-scscf-mobile-fixed-auth.patch
docker compose up -d --force-recreate scscf
```

For the previously delivered merged lab, use
`ims-scscf-mobile-fixed-auth-merged.patch` instead; its paths begin with `ims/`.
The patches are checked against their corresponding supplied baselines.
Kamailio itself is not run locally; validate its startup and capture the new MAR
on the target lab. Keep MySQL TLS disabling and authentication policy provisioning
as separate operator settings.

## Validation and scope

The included Cx tests generate synthetic identities, realms, keys and passwords,
then use actual native database rows, Diameter encoding/decoding and Milenage.
Run them with the existing repository test configuration:

```sh
PYHSS_CONFIG=tests/config.yaml PYTHONPATH=lib python -m pytest tests/test_cx_registration.py -q
```

For database backend tests, set `PYHSS_CX_TEST_URL` to an empty disposable
database whose name begins with `pyhss_test_cx`. These tests reset that selected
database. See `cx-validation.json` for the package's checks and earlier backend
validation. Live SIP registration on the target S-CSCF remains to be validated.

This patch addresses the reviewed distinct-user Cx registration procedures.
Optional IMS restoration, PSI/wildcard identities, NASS/GIBA and WebRTC are not
implemented or advertised. Native PPR and complete per-private/implicit-set
GeoRed replication are outside this change. It is not full-stack 3GPP certification.

References: [TS 29.228](https://www.etsi.org/deliver/etsi_ts/129200_129299/129228/18.00.00_60/ts_129228v180000p.pdf),
[TS 29.229](https://www.etsi.org/deliver/etsi_ts/129200_129299/129229/18.00.00_60/ts_129229v180000p.pdf),
[Kamailio ims_auth](https://github.com/kamailio/kamailio/blob/master/src/modules/ims_auth/authorize.c).
