# GM Global B SecOC

## Overview

Global B uses an authenticated CAN format that differs from AUTOSAR SecOC. The
authenticator and freshness lead the application payload. The secured PDUs in
the variant currently cataloged here carry five freshness bits and each has a
separate companion frame that periodically publishes its full counter. That is
not a rule for every Global B secured PDU: another profile carries its complete
64-bit freshness in the secured frame and has no companion.

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
layout. For the currently defined ACP3_MCU scheme, `data_id` is `1` and freshness is
a 32-bit counter represented in the low half of the 64-bit freshness input.

The security prefix itself is not part of `application_payload`:

| Layout | Bytes 0 through 3 | Byte 4 | Payload begins |
| --- | --- | --- | --- |
| 27-bit MAC | 27-bit MAC followed by freshness bits 4:0 | payload | byte 4 |
| 32-bit MAC | 32-bit MAC | freshness bits 4:0 in bits 7:3; auxiliary bits in bits 2:0 | byte 5 |

In the 27-bit layout, the four-byte prefix consists of the 27-bit MAC followed
immediately by the five low freshness bits. In the 32-bit layout, three
preserved auxiliary bits complete the five-byte prefix. They are not part of the
application payload supplied to CMAC.

## Freshness and companion frames

In the cataloged variant, each secured PDU has a distinct logical 32-bit
freshness stream. The secured frame carries only its low five bits. Its
configured companion frame periodically publishes the full counter as a
little-endian `u32` in bytes 0 through 3, with any remaining companion bytes
zero-filled. Other schemes can share a freshness stream, which is why opendbc
identifies counters with `fv_id` rather than assuming the CAN ID universally
owns one.

The secured PDU and companion are independently scheduled messages. Each
transmission takes the next value from their shared stream, including the
companion itself. Around a lossless companion transmission, the sequence is
therefore:

```text
secured(N - 1), companion(N), secured(N + 1)
```

There is no universal companion phase or integer "secured frames per companion"
rule. Most captured pairs happen to have integer cycle-time ratios, but a 1000
ms secured PDU with a 3500 ms companion alternates between three and four
secured transmissions. The DBC therefore gives each PDU its own
`GenMsgCycleTime`; callers publish the companion on that schedule with
`publish_freshness()`.

A receiver with an accepted full value `anchor` reconstructs a five-bit value
`received` as the smallest congruent value strictly after the anchor:

```text
mask      = (1 << 5) - 1
candidate = (anchor & ~mask) | received
if (anchor & mask) >= received:
  candidate += 1 << 5
```

The resulting forward window is exactly `anchor + 1` through `anchor + 32`,
with no backward allowance. A repeated low-five value resolves to
`anchor + 32`, not to the already accepted value. Authentication still has to
succeed for that reconstructed full freshness before the anchor advances. A
sender joining an active bus starts after the newest observed full value and
never moves its counter backward.

Freshness arithmetic wraps at 32 bits for both the CMAC input and the companion
frame.

### What the captures establish

Across four captures, all 14 secured PDUs in this variant had their configured,
distinct companion on the same bus. In steady traffic:

| Secured cycle | Companion cycle | Secured frames between companions | Companion-value step |
| ---: | ---: | ---: | ---: |
| 10 or 50 ms | 160 or 800 ms | 16 | 17 |
| 100 ms | 1000 ms | 10 | 11 |
| 1000 ms | 3500 ms | alternating 3 and 4 | alternating 4 and 5 |

The extra one in each value step is the companion's own counter tick. Startup
traffic contains shorter gaps, another reason not to infer phase from a fixed
counter residue. These passive captures confirm sender layout, counter
progression, and scheduling; they cannot by themselves test which deliberately
stale values a receiver rejects.

## Is it just one key?

No. A single module can use multiple keys to sign different messages, or use
them for other purposes, including IP traffic.

## What are the three low bits in byte 4 of the 32-bit layout?

Opaque security-prefix slack, not application status, zero padding, MAC, or
freshness bits. Across the four captures, it is zero in 101,779 of 105,122
frames (96.82%). All seven nonzero values occur, but 96.3% of nonzero events
last exactly one frame. Related PDUs transmitted at the same timestamp almost
never become nonzero together, and the value does not track freshness or the
adjacent payload. There is therefore no evidence that it encodes persistent
application state; `AUX` deliberately makes no stronger claim.

The authenticated payload begins at byte 5. Authentication preserves the
auxiliary input value while replacing the MAC and freshness fields. Since the
CMAC payload begins at byte 5, changing these bits does not change the MAC.

## DBC contract

The DBC describes each secured message with `AUTHENTICATOR` and
`SECOC_FRESHNESS` signals. A 32-bit layout also declares `SECOC_AUX` to make
the complete five-byte prefix explicit. Message attributes provide the data ID,
key role, and companion CAN ID:

- `SecOCDataId`
- `SecOCKeyRole`
- `SecOCCompanionId`

The companion's ordinary `GenMsgCycleTime` describes its independent schedule.
Together, the signal widths and attributes define everything that varies by
message; the CMAC construction and byte order are common to the scheme.

## Why distinguish key roles and families?

`SecOCKeyRole` identifies the exact logical key a frame must use, and roles remain distinct even when sampled vehicles provision them with identical key bytes. `SecOCObservedKeyFamily` records that observed equality without making it a runtime guarantee, while `SecOCKeyCandidates` lists the possible roles when identical bytes prevent an exact assignment. This distinction exists because HSM slots are local to each ECU and provisioning can differ across vehicles or variants, so collapsing observed duplicates could select the wrong key later.
