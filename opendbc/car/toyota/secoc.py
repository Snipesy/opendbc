"""Toyota TSS2 message authentication.

AUTOSAR SecOC as Toyota ships it, and the scheme opendbc supported first. The authenticator
trails the payload: a 48 bit freshness value is built from the trip and reset counters the car
broadcasts on SECOC_SYNCHRONIZATION plus a per-message counter, and the frame carries the four
low bits of that counter beside a 28 bit truncated AES-128-CMAC.

The car's own SECOC_SYNCHRONIZATION frame is itself authenticated, which is what lets a wrong
key be detected before anything is transmitted; see SecOcAuthenticator.verify_sync().
"""

from opendbc.car.secoc import MAC, SecOcCatalog, SecOcMessage, SecOcProfile

# 28 bit truncated AES-128-CMAC over [address][4 byte payload][freshness]. The tail follows the
# payload: 2 bits each of the message and reset counters, then the MAC. The low bits of those
# counters appear beside the full ones: a layout field is the counter masked to its width, so
# the same name serves. The signal aliases are the names toyota_secoc_pt declares, so
# layout_from_dbc() can read these bit positions back out of the DBC.
TOYOTA_SECOC = SecOcProfile(
  header_layout=(('data_id', 16),),
  freshness_layout=(('trip', 16), ('reset', 20), ('msg', 8), ('reset', 2), ('pad', 2)),
  tail_layout=(('msg', 2), ('reset', 2), (MAC, 28)),
  tail_offset=4,
  signals=((MAC, 'AUTHENTICATOR'), ('msg', 'MSG_CNT_LOWER'), ('reset', 'RESET_FLAG')),
)

# The synchronization message's MAC, SecOC 11.4.1.1 page 138: the same construction over an id
# and the trip and reset counters, with no payload.
TOYOTA_SYNC = SecOcProfile(
  header_layout=(('id', 16),),
  freshness_layout=(('trip', 16), ('reset', 20), ('pad', 4)),
  tail_layout=((MAC, 28),),
)
TOYOTA_SYNC_ID = 0xF

# The one key a Toyota carries, shared by every secured message and the synchronization frame.
KEY_VEHICLE = 'vehicle'

# Messages openpilot transmits, all on bus 0 and all signed by the vehicle key. Each gets its
# own freshness id, so each carries an independent counter. None of them has a companion
# frame: the freshness is in-band.
TOYOTA_CATALOG = SecOcCatalog(
  SecOcMessage(bus=0, addr=addr, profile=TOYOTA_SECOC, data_id=addr, fv_id=addr, key_id=KEY_VEHICLE)
  for addr in (0x2E4, 0x131, 0x183)  # STEERING_LKA, STEERING_LTA_2, ACC_CONTROL_2
)
