# PyHSS Cx registration patch

This package contains replacement and new files for the supplied PyHSS source,
with repository-relative paths. Extract its contents into your fork's root and
upload the files in their existing folders. Install the updated requirements
and restart the PyHSS services. Your existing native subscriber and AuC records
remain the source of credentials; Cx uses the configured PyHSS SQLAlchemy engine.
The supplied archive's native UDR/PCF model additions are retained.

Alternatively, apply the accompanying `pyhss-cx-repo-ready.patch` from your fork:

```sh
git apply --check /path/to/pyhss-cx-repo-ready.patch
git apply /path/to/pyhss-cx-repo-ready.patch
python -m pip install -r requirements.txt
```

The patch is checked against the supplied `pyhss-master (1).zip`. If your fork
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
| `authentication_scheme` | `SIP Digest` for fixed Digest authentication or `Digest-AKAv1-MD5` for AKA |
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

Set `hss.cx.server_capabilities` to the operator's actual `mandatory` and
`optional` capability lists when capability-based S-CSCF selection is used.
No capability IDs or S-CSCF endpoints are invented by the new Cx handlers.

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
