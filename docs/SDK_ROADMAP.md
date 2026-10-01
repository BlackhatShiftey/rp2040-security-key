# Canticle Key SDK roadmap

**Status: planned.** The current release is an RP2040-Zero-specific Pico FIDO
derivative and verification package. The SDK architecture below is a direction for
future work; these interfaces and platform capabilities are not shipped today.

## Goal

Create a source-first framework that separates board support, authenticator policy,
and host tooling while preserving explicit security capabilities and reproducible
qualification. A board profile should state what it can protect instead of allowing
the firmware to imply secure storage or entropy guarantees the hardware does not have.

## Proposed modules

### Board support

A versioned board profile would describe:

- MCU, flash layout, and supported boot/update method;
- user-presence inputs and LED/output mapping;
- secure-storage capabilities and physical-extraction limits;
- entropy source and health-check requirements;
- USB controller constraints and allowed identity configuration;
- PIN/UV policy limits and supported authenticator profiles.

Profiles would be data plus a small hardware interface. Firmware code would consume
capabilities through that interface instead of scattering board-specific conditionals.

### FIDO core

The authenticator core would keep CTAP state transitions, credential policy, and
presence enforcement independent from board GPIO and USB details. Security-relevant
operations would accept explicit capability and policy objects. Unsupported guarantees
would fail closed with a versioned error instead of silently degrading.

### Host API

A future host API would expose a stable, machine-readable surface for:

- device discovery and exact-target selection;
- capability and configuration reads;
- guarded provisioning and readback receipts;
- synthetic qualification runs;
- PIN-aware verification without accepting PINs in command arguments;
- structured, sanitized results suitable for CI or audit tooling.

The API would not provide account enrollment automation or export private credential
material. Interactive secrets would remain on a controlling terminal or trusted OS UI.

### Versioned errors and receipts

Errors should have stable codes, a schema version, an operation phase, and a safe
human message. Receipts should bind the source lock, patch set, build configuration,
artifact digest, target profile, and completed checks. Raw credentials, PINs, recovery
codes, USB serials, and machine paths must never appear in public receipts.

## Proposed delivery phases

1. **Profile schema:** extract the RP2040-Zero GPIO, flash, entropy, USB, and PIN policy
   assumptions into a versioned board profile.
2. **Firmware boundary:** define board, storage, entropy, presence, and USB interfaces
   around the existing Pico FIDO core.
3. **Host protocol:** publish versioned discovery, configuration, provisioning, and
   qualification result schemas.
4. **Second target:** add another board only after its storage and entropy claims have
   explicit tests and a separate qualification record.
5. **Release discipline:** bind source locks, generated artifacts, SBOM/license data,
   and hardware evidence without carrying operator-private records into releases.

## Acceptance principles

- Each supported board has its own threat model and qualification matrix.
- Secure storage, entropy, USB identity, and PIN policy are declared capabilities.
- Unsupported security properties fail closed.
- Firmware artifacts are qualified by digest; results do not transfer across builds.
- Host APIs use versioned schemas and errors before compatibility is promised.
- Account-service compatibility remains a separate integration test.

Until these phases land, references to the Canticle Key SDK describe roadmap work,
not an available SDK or a claim of multi-board support.
