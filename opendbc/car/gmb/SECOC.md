# GM Global B SecOC

## Overview

Global B uses an authenticated CAN format that differs from AUTOSAR SecOC. The
authenticator and truncated freshness lead the application payload, and each
secured PDU has a separate companion frame that periodically publishes its full
freshness counter.

Most CAN frames are not secured. Authentication is defined per message, not per
bus or module.

## Authentication algorithm

Each secured message selects a key, one-byte data ID, CAN ID, and freshness
counter. Its full authentication input is:

```text
data_id[1] || BE32(can_id) || BE64(freshness) || application_payload
```

The authenticator is AES-CMAC over that byte string. The wire carries the most
significant 27 or 32 bits of the 128-bit CMAC, according to the message's DBC
layout. For the currently defined IPM scheme, `data_id` is `1` and freshness is
a 32-bit counter represented in the low half of the 64-bit freshness input.

The security prefix itself is not part of `application_payload`:

| Layout | Bytes 0 through 3 | Byte 4 | Payload begins |
| --- | --- | --- | --- |
| 27-bit MAC | 27-bit MAC followed by freshness bits 4:0 | payload | byte 4 |
| 32-bit MAC | 32-bit MAC | freshness bits 4:0 in bits 7:3; reserved padding in bits 2:0 | byte 5 |

In the 27-bit layout, the four-byte prefix consists of the 27-bit MAC followed
immediately by the five low freshness bits. In the 32-bit layout, the 37 defined
security bits occupy a five-byte prefix and leave three alignment bits unused.

## Freshness and companion frames

Each secured PDU has an independent 32-bit freshness counter. The secured frame
carries only its low five bits. Its configured companion frame periodically
publishes the full counter as a little-endian `u32` in bytes 0 through 3, with
any remaining companion bytes zero-filled.

The counter advances for every transmitted secured frame and for the companion
frame itself. Around a companion transmission, the sequence is therefore:

```text
secured(N - 1), companion(N), secured(N + 1)
```

If the configured companion period is `P` secured frames, consecutive companion
values differ by `P + 1`. A sender joining an active bus starts after the newest
observed full freshness value and never moves its counter backward.

Freshness arithmetic wraps at 32 bits for both the CMAC input and the companion
frame.

## Is it just one key?

No. A single module can use multiple keys to sign different messages, or use
them for other purposes, including IP traffic.

## What are the three low bits in byte 4 of the 32-bit layout?

Reserved byte-alignment padding. They are not a status field and are not
authenticated.

The authenticated payload begins at byte 5. Authentication preserves the
padding's input value while replacing the MAC and freshness fields, but changing
the padding cannot change the MAC. A normally packed frame leaves it zero.

## DBC contract

The DBC describes each secured message with `AUTHENTICATOR` and
`SECOC_FRESHNESS` signals. A 32-bit layout also declares `SECOC_PADDING` to make
the complete five-byte prefix explicit. Message attributes provide the data ID,
key role, companion CAN ID, and companion period:

- `SecOCDataId`
- `SecOCKeyRole`
- `SecOCCompanionId`
- `SecOCCompanionPeriod`

Together, the signal widths and attributes define everything that varies by
message; the CMAC construction and byte order are common to the scheme.

## Why distinguish key roles and families?

`SecOCKeyRole` identifies the exact logical key a frame must use, and roles remain distinct even when sampled vehicles provision them with identical key bytes. `SecOCObservedKeyFamily` records that observed equality without making it a runtime guarantee, while `SecOCKeyCandidates` lists the possible roles when identical bytes prevent an exact assignment. This distinction exists because HSM slots are local to each ECU and provisioning can differ across vehicles or variants, so collapsing observed duplicates could select the wrong key later.
