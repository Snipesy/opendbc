# Quick Rundown

## Is it secoc?

More or less, the format is just different and non standard.

Note most CAN Frames DO NOT HAVE SECOC (i.e. plaintext). Likewise, many modules
may simply ignore the authentication even if it is present.

## Is it just one key?

No. A single module can use multiple keys to sign different messages, or use
it for other purposes including IP (Ethernet)

## Why distinguish key roles and families?

`SecOCKeyRole` identifies the exact logical key a frame must use, and roles remain distinct even when sampled vehicles provision them with identical key bytes. `SecOCObservedKeyFamily` records that observed equality without making it a runtime guarantee, while `SecOCKeyCandidates` lists the possible roles when identical bytes prevent an exact assignment. This distinction exists because HSM slots are local to each ECU and provisioning can differ across vehicles or variants, so collapsing observed duplicates could select the wrong key later.
