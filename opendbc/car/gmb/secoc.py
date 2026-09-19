"""GM Global B message authentication.

One vehicle variant is described per Scheme: the module openpilot stands in for, the DBCs of
the buses it reaches, and how those buses map onto port roles. SUPERCRUISE1 is the IPM on a
Super Cruise car, numbered because it is one scheme seen on Global B rather than the only one.
A car without Super Cruise has the FCM send the secured control frames instead; that is a
second Scheme over its own DBCs, and nothing else here has to change for it.

The scheme label describes the variant, not the message set -- it also covers frames that
have nothing to do with Super Cruise, such as the body and comfort configuration frame. It is
carried by the DBC filenames rather than by anything in this module, because the authenticator
layouts themselves are not specific to it.

SecOC-shaped but not AUTOSAR SecOC. Three differences drive everything here:

  * In the profiles cataloged here, the freshness value is a plain 32 bit counter published in
    the clear on a companion frame, one per secured PDU on the same bus. The secured frame
    carries only its low 5 bits, so a receiver resolves the full value from the companion. The
    counter advances once per frame transmitted, the companion included. Other profiles may
    carry their full freshness in-band and need no companion.
  * The authenticator leads the frame and the payload follows it, and its width varies per
    message: 27 bits with the payload at offset 4, or 32 bits with the payload at offset 5.
    Which one a message uses is a property of that message, not of the platform.
  * Keys bind to a frame on a bus, not to the module that sends it. One module's frames can be
    signed by several different keys, and a key covers frames from several modules. So key_id
    is a property of each catalog entry, and it is a name rather than a storage location.

The MAC input is CMAC_k(data_id || BE32(can_id) || BE64(freshness) || payload), with a
constant data_id of 1. Note how far that is from AUTOSAR's, which is
data_id(16 bit) || payload || freshness with the authenticator trailing the payload: the data
id is a byte rather than two, the CAN id is folded in, the freshness leads the payload instead
of following it, and the authenticator sits at the front of the frame.

The catalog is built from the DBCs rather than written out here: a secured message's address,
length, authenticator layout, bus, key role and companion all come from them, the same way
Toyota's layout comes from the AUTHENTICATOR, RESET_FLAG and MSG_CNT_LOWER signals its DBC
declares. What a DBC cannot state stays below -- the MAC construction and freshness layout.

Bus numbers here are VEHICLE bus numbers. opendbc has no notion of those: its buses are the
indices a panda is wired to, named per brand in CanBus. Binding one to the other is
Scheme.port_catalog()'s job, and only the vehicle buses a port actually reaches survive it.
"""

from dataclasses import dataclass, replace
from functools import cached_property

from opendbc.can.dbc import DBC
from opendbc.car import Bus
from opendbc.car.secoc import MAC, Companion, SecOcCatalog, SecOcMessage, SecOcProfile, layout_from_dbc

# Signals a secured message may declare, and the tail field each one is. The three bits beside
# the 32 bit layout's freshness are preserved auxiliary wire state. They are outside the MAC
# input; their application meaning is not needed to authenticate the PDU.
SECOC_SIGNALS = ((MAC, "AUTHENTICATOR"), ("msg", "SECOC_FRESHNESS"), ("aux", "SECOC_AUX"))

# The two tail layouts. These are a property of the scheme rather than of any one platform or
# feature, so they are named for the shape and nothing else: which one a message uses is its
# DBC's to say, through the width of its AUTHENTICATOR and whether it declares SECOC_AUX
# field. A Scheme refuses anything outside its layouts, so a change to a DBC that yields some
# third layout is visible rather than silently absorbed.
#
# 27 bit: authenticator in bytes 0..2 plus the top 3 bits of byte 3, truncated counter in the
# low 5 bits of byte 3, payload from offset 4.
LAYOUT_27 = SecOcProfile(
  header_layout=(("data_id", 8), ("addr", 32)),
  # the counter is u32 on the wire, carried in a 64 bit field, so it must wrap where the
  # companion frame and the sending ECU both wrap
  freshness_layout=(("pad", 32), ("msg", 32)),
  tail_layout=((MAC, 27), ("msg", 5)),
  freshness_before_payload=True,
  signals=SECOC_SIGNALS[:2],
)

# 32 bit: authenticator in bytes 0..3, counter in the top 5 bits of byte 4, payload from
# offset 5. The low 3 bits of byte 4 are auxiliary wire state, not padding or MAC/counter bits.
# They are preserved from the packer's frame and are outside the authenticated payload.
LAYOUT_32 = replace(LAYOUT_27, tail_layout=((MAC, 32), ("msg", 5), ("aux", 3)), signals=SECOC_SIGNALS)

# What a DBC may yield, as (tail layout, tail offset).
LAYOUTS = frozenset((p.tail_layout, p.tail_offset) for p in (LAYOUT_27, LAYOUT_32))

KEY_ROLE_ATTR = "SecOCKeyRole"
DATA_ID_ATTR = "SecOCDataId"
COMPANION_ID_ATTR = "SecOCCompanionId"
CYCLE_TIME_ATTR = "GenMsgCycleTime"


def reconstruct_freshness(anchor: int, truncated: int, bits: int = 5) -> int:
  """Return the smallest freshness strictly after anchor with the received low bits.

  For the five-bit profiles this accepts a candidate in anchor + 1 through anchor + 32 and
  gives no backward allowance. A repeated low-five value therefore means anchor + 32, not the
  already accepted anchor.
  """
  if bits <= 0:
    raise ValueError("freshness width must be positive")
  modulus = 1 << bits
  delta = (truncated - anchor) & (modulus - 1)
  return anchor + (delta or modulus)


def _required_int_attr(dbc_name: str, msg_name: str, attrs: dict[str, str | int | float], name: str) -> int:
  value = attrs.get(name)
  if not isinstance(value, int):
    raise ValueError(f"{dbc_name}: {msg_name} requires integer message attribute {name}")
  return value


@dataclass(frozen=True, eq=False)
class Scheme:
  """The secured frames one module transmits on one vehicle variant.

  The catalog is built from the DBCs rather than written out here: every secured message the
  DBC says `transmitter` sends, with the address, length, layout, key role, data id and
  companion each one declares. What a DBC cannot state is the MAC construction, which is the
  base profile, and which tail layouts the scheme admits.
  """
  name: str
  # one complete DBC per physical vehicle bus. The files contain both transmitted and received
  # traffic; direction comes from the transmitter the DBC names on each message, so secured
  # PDUs other modules send, such as 0x27B on CAN2, never become signable
  dbcs: dict[int, str]
  transmitter: str
  # the role each vehicle bus carries. Buses left unroled cannot be bound to a port, which is
  # deliberate: where a role lands stays the port's business, so this module never has to know
  # how a brand numbers its buses or what offset a multi-panda harness adds
  bus_roles: dict[int, Bus]
  profile: SecOcProfile = LAYOUT_27
  layouts: frozenset[tuple] = LAYOUTS

  @cached_property
  def catalog(self) -> SecOcCatalog:
    mac_signal = dict(SECOC_SIGNALS)[MAC]
    messages = []
    for bus, dbc_name in self.dbcs.items():
      dbc = DBC(dbc_name)
      for name, dbcmsg in dbc.name_to_msg.items():
        if dbcmsg.transmitter != self.transmitter or mac_signal not in dbcmsg.sigs:
          continue
        key_id = dbcmsg.attrs.get(KEY_ROLE_ATTR)
        if not isinstance(key_id, str) or not key_id:
          raise ValueError(f"{dbc_name}: {name} requires non-empty message attribute {KEY_ROLE_ATTR}")
        companion_addr = _required_int_attr(dbc_name, name, dbcmsg.attrs, COMPANION_ID_ATTR)
        companion = dbc.addr_to_msg.get(companion_addr)
        if companion is None:
          raise ValueError(f"{dbc_name}: {name} declares missing companion 0x{companion_addr:X}")

        signals = tuple((field, sig) for field, sig in SECOC_SIGNALS if sig in dbcmsg.sigs)
        layout = layout_from_dbc(dbcmsg, signals)
        if layout not in self.layouts:
          raise ValueError(f"{dbc_name}: {name} declares an authenticator layout {self.name} does not know: {layout}")
        messages.append(
          SecOcMessage(
            bus=bus,
            addr=dbcmsg.address,
            profile=replace(self.profile, tail_layout=layout[0], tail_offset=layout[1], signals=signals),
            data_id=_required_int_attr(dbc_name, name, dbcmsg.attrs, DATA_ID_ATTR),
            # This variant's captured PDUs each have a distinct companion and logical counter.
            # The generic SecOcMessage still permits another scheme to share an fv_id.
            fv_id=dbcmsg.address,
            key_id=key_id,
            companion=Companion(companion.address, companion.size,
                                _required_int_attr(dbc_name, companion.name, companion.attrs, CYCLE_TIME_ATTR)),
          )
        )
    return SecOcCatalog(messages)

  def port_catalog(self, bus_indices: dict[Bus, int]) -> SecOcCatalog:
    """The catalog re-indexed onto a CarController's bus numbering.

    Give the bus index this port reaches each role on, straight from the brand's CanBus:

        SUPERCRUISE1.port_catalog({Bus.pt: CanBus.POWERTRAIN})

    Any offset a harness needs is already in the value the caller passes. Roles the port does
    not list, and vehicle buses with no role, are dropped rather than silently renumbered --
    reaching a further bus is a longer call, not an edit here.
    """
    return self.catalog.rebus({vehicle: bus_indices[role] for vehicle, role in self.bus_roles.items() if role in bus_indices})


# The IPM on a Super Cruise car. Only vehicle bus 2 is roled: it is the powertrain segment,
# and the one the IPM sends its control frames on. The rest are left unroled rather than
# guessed.
SUPERCRUISE1 = Scheme(
  name="supercruise1",
  dbcs={
    2: "gm_global_b_supercruise1_secoc_bus2",
    3: "gm_global_b_supercruise1_secoc_bus3",
    8: "gm_global_b_supercruise1_secoc_bus8",
  },
  transmitter="IPM",
  bus_roles={2: Bus.pt},
)
