import struct

import pytest

from opendbc.can.dbc import DBC
from opendbc.car import Bus
from opendbc.car.gmb.secoc import LAYOUT_27, SUPERCRUISE1, Scheme
from opendbc.car.gm.values import CanBus
from opendbc.car.secoc import SecOcAuthenticator, SecOcCatalog, SecOcMessage, aes_cmac, authenticate

KEY = bytes(range(16))
GM_CATALOG = SUPERCRUISE1.catalog

# Synthetic frames covering both layouts and both DLC families.
GM_FRAMES = [
  (0x0BB, 0x0BD3E142, "00000002" + "aa" * 3),  # 27 bit, 7 byte
  (0x271, 0x0AC9629C, "0000001c" + "bb" * 4),  # 27 bit, 8 byte
  (0x057, 0x1181C862, "0000000010" + "dd" * 27),  # 32 bit, 32 byte
  (0x24B, 0x0ABEB919, "00000000c8" + "ee" * 7),  # 32 bit, 12 byte
  (0x284, 0x1181C85E, "00000000f4" + "ff" * 7),  # 32 bit, 12 byte, auxiliary bits set
]

# Explicit protocol inventory. The catalog is derived from the DBCs' transmitter and signal
# declarations, so this is the independent statement of what those must yield: a DBC edit that
# drops or adds a secured IPM message cannot make the test agree with itself. Values are
# (companion address, authenticator width, secured frames per companion).
EXPECTED_TX = {
  (2, 0x057): (0x392, 32, 16),
  (2, 0x0BB): (0x39F, 27, 16),
  (2, 0x20D): (0x39D, 27, 16),
  (2, 0x20E): (0x386, 32, 16),
  (2, 0x24B): (0x3CB, 32, 16),
  (2, 0x271): (0x39C, 27, 16),
  (2, 0x284): (0x3CE, 32, 16),
  (2, 0x45D): (0x79D, 27, 3),
  (2, 0x52B): (0x567, 27, 3),
  (2, 0x52D): (0x571, 27, 3),
  (3, 0x210): (0x29F, 32, 16),
  (3, 0x265): (0x579, 27, 16),
  (3, 0x371): (0x575, 27, 10),
  (8, 0x021): (0x372, 27, 16),
}


class TestGmGlobalB:
  """GM publishes freshness in the clear on a companion frame, so the frame layout is pinned
  by recorded traffic even without a signing key. These tests pin the construction itself."""

  @pytest.mark.parametrize("addr, freshness, frame", GM_FRAMES)
  def test_mac_input_matches_the_documented_construction(self, addr, freshness, frame):
    # CMAC_k(data_id || BE32(can_id) || BE64(freshness) || payload), data_id = 1
    msg = GM_CATALOG[(2, addr)]
    src = bytes.fromhex(frame)
    tail = msg.profile.tail_len
    expected = aes_cmac(KEY, bytes([1]) + struct.pack(">I", addr) + struct.pack(">Q", freshness) + src[tail:])
    want = int.from_bytes(expected, "big") >> (8 * len(expected) - msg.profile.mac_bits)

    _, out, _ = authenticate(KEY, msg, {'msg': freshness}, (addr, src, 0))
    got = int.from_bytes(out[:tail], "big") >> (8 * tail - msg.profile.mac_bits)
    assert got == want

  @pytest.mark.parametrize("addr, freshness, frame", GM_FRAMES)
  def test_payload_and_length_are_preserved(self, addr, freshness, frame):
    msg = GM_CATALOG[(2, addr)]
    src = bytes.fromhex(frame)
    _, out, _ = authenticate(KEY, msg, {'msg': freshness}, (addr, src, 0))
    assert len(out) == len(src)
    assert out[msg.profile.tail_len :] == src[msg.profile.tail_len :]

  @pytest.mark.parametrize("addr, freshness, frame", GM_FRAMES)
  def test_in_band_freshness_is_the_counter_low_bits(self, addr, freshness, frame):
    msg = GM_CATALOG[(2, addr)]
    _, out, _ = authenticate(KEY, msg, {'msg': freshness}, (addr, bytes.fromhex(frame), 0))
    in_band = out[3] & 0x1F if msg.profile.mac_bits == 27 else out[4] >> 3
    assert in_band == freshness & 0x1F

  def test_auxiliary_bits_beside_the_freshness_are_preserved(self):
    # byte 4 of the 32 bit layout carries three semantically unknown auxiliary bits below the
    # freshness; they belong to the packer's frame and the authenticator must not clobber them
    msg = GM_CATALOG[(2, 0x284)]
    for aux in range(8):
      src = bytes([0, 0, 0, 0, aux]) + b"\x11" * 7
      _, out, _ = authenticate(KEY, msg, {'msg': 0x1181C85E}, (0x284, src, 0))
      assert out[4] & 0x07 == aux
      assert out[4] >> 3 == 0x1181C85E & 0x1F

  def test_refuses_a_frame_too_short_to_sign(self):
    # truncating instead would emit a short frame that presents as a bad key downstream
    msg = GM_CATALOG[(2, 0x284)]
    with pytest.raises(ValueError, match="too short"):
      authenticate(KEY, msg, {}, (0x284, bytes(msg.profile.tail_len), 0))
    _, out, _ = authenticate(KEY, msg, {}, (0x284, bytes(msg.profile.tail_len + 1), 0))
    assert len(out) == msg.profile.tail_len + 1

  def test_freshness_wraps_as_a_u32(self):
    # the wire counter is 32 bit, and companion() masks it, so the MAC input must wrap with it
    msg = GM_CATALOG[(2, 0x284)]
    frame = (0x284, bytes(12), 0)
    sign = lambda cnt: authenticate(KEY, msg, {'msg': cnt}, frame)  # noqa: E731
    assert sign(1 << 32) == sign(0)
    assert sign((1 << 32) + 7) == sign(7)
    assert sign(7) != sign(8)

  def test_observe_freshness_never_moves_a_counter_backwards(self):
    # a sender coming up mid-drive starts after the observed tick rather than replaying it
    auth = SecOcAuthenticator(GM_CATALOG, KEY)
    auth.observe_freshness((2, 0x271), 0x0AC9629C)
    assert auth.msg_cnt[(2, 0x271)] == 0x0AC9629D

    auth.observe_freshness((2, 0x271), 0x0AC96200)
    assert auth.msg_cnt[(2, 0x271)] == 0x0AC9629D, "a stale reading must not rewind the counter"

    ((_, secured, _),) = auth.secure((0x271, bytes(8), 2))
    assert secured[3] & 0x1F == 0x0AC9629D & 0x1F

  def test_observe_freshness_advances_across_u32_wrap(self):
    auth = SecOcAuthenticator(GM_CATALOG, KEY)
    auth.msg_cnt[(2, 0x271)] = 0xFFFFFFFF
    auth.observe_freshness((2, 0x271), 0xFFFFFFFF)
    assert auth.msg_cnt[(2, 0x271)] == 0x100000000

    ((_, secured, _),) = auth.secure((0x271, bytes(8), 2))
    assert secured[3] & 0x1F == 0

  def test_companion_consumes_a_counter_tick(self):
    # the wire reads ... secured N-1, companion N, secured N+1 ...
    auth = SecOcAuthenticator(GM_CATALOG, KEY)
    period = GM_CATALOG[(2, 0x271)].companion.period
    auth.msg_cnt[(2, 0x271)] = 17 * 6  # aligned so the companion lands on the period-th frame

    for _ in range(period - 1):
      auth.secure((0x271, bytes(8), 2))

    frames = auth.secure((0x271, bytes(8), 2))
    assert len(frames) == 2, "the period-th secured frame is followed by its companion"
    (_, before, _), (comp_addr, comp_data, _) = frames
    assert comp_addr == 0x39C

    published = struct.unpack("<I", comp_data[:4])[0]
    assert before[3] & 0x1F == (published - 1) & 0x1F, "secured frame before it is one lower"

    ((_, after, _),) = auth.secure((0x271, bytes(8), 2))
    assert after[3] & 0x1F == (published + 1) & 0x1F, "the next one is one higher, not equal"

  def test_counter_steps_by_period_plus_one_between_companions(self):
    auth = SecOcAuthenticator(GM_CATALOG, KEY)
    period = GM_CATALOG[(2, 0x271)].companion.period
    published = []
    for _ in range(period * 4):
      for addr, data, _bus in auth.secure((0x271, bytes(8), 2)):
        if addr == 0x39C:
          published.append(struct.unpack("<I", data[:4])[0])

    assert len(published) == 4, f"one companion per {period} secured frames"
    assert {b - a for a, b in zip(published, published[1:], strict=False)} == {period + 1}

  def test_every_message_has_a_distinct_companion_on_its_own_bus(self):
    assert all(m.companion is not None for m in GM_CATALOG)
    seen = {(m.bus, m.companion.addr) for m in GM_CATALOG}
    assert len(seen) == len(GM_CATALOG), "two messages share a companion"
    assert not seen & {m.ref for m in GM_CATALOG}, "a companion collides with a secured id"

  def test_catalog_matches_the_protocol_inventory(self):
    assert {msg.ref for msg in GM_CATALOG} == set(EXPECTED_TX)
    for ref, (companion_addr, mac_bits, companion_period) in EXPECTED_TX.items():
      msg = GM_CATALOG[ref]
      assert (msg.companion.addr, msg.profile.mac_bits, msg.companion.period) == (companion_addr, mac_bits, companion_period)

      dbc = DBC(f"gm_global_b_supercruise1_secoc_bus{msg.bus}")
      dbcmsg = dbc.addr_to_msg[msg.addr]
      assert msg.profile.tail_len < dbcmsg.size

  def test_receive_pdus_are_not_signable(self):
    assert GM_CATALOG.key_ids == {"safety_control_key"}
    assert (2, 0x27B) not in GM_CATALOG
    assert (2, 0x2B6) not in GM_CATALOG

  def test_catalog_is_exactly_what_the_ipm_transmits_and_secures(self):
    # direction comes from the DBC's transmitter, not from a list kept beside it
    for bus, dbc_name in SUPERCRUISE1.dbcs.items():
      for msg in DBC(dbc_name).msgs.values():
        secured_by_ipm = msg.transmitter == SUPERCRUISE1.transmitter and "AUTHENTICATOR" in msg.sigs
        assert ((bus, msg.address) in GM_CATALOG) == secured_by_ipm, f"{dbc_name} {msg.name}"

  def test_a_scheme_is_one_module_on_one_variant(self):
    # the same DBCs seen from another module yield that module's secured frames: the CGM
    # transmits on every bus here and secures nothing, so its catalog is empty
    cgm = Scheme(name="cgm", dbcs=SUPERCRUISE1.dbcs, transmitter="CGM", bus_roles={2: Bus.pt})
    assert len(cgm.catalog) == 0
    assert cgm.catalog is cgm.catalog, "built once, on first use"

    # a scheme admitting only the 32 bit layout refuses the DBCs' 27 bit messages by name
    narrow = Scheme(name="narrow", dbcs=SUPERCRUISE1.dbcs, transmitter="IPM", bus_roles={2: Bus.pt},
                    layouts=frozenset({((('mac', 32), ("msg", 5), ("flags", 3)), 0)}))
    with pytest.raises(ValueError, match="narrow does not know"):
      narrow.catalog  # noqa: B018
    assert SUPERCRUISE1.profile is LAYOUT_27, "the MAC construction is the scheme's to choose"

  def test_dbc_declares_known_key_roles_per_message(self):
    expected_bus2 = {
      "safety_control_key": {0x03A, 0x054, 0x057, 0x0BB, 0x20D, 0x20E, 0x24B, 0x271, 0x284, 0x45D, 0x52B, 0x52D},
      "shared_secoc_key_a": {0x03B, 0x042, 0x270, 0x27B, 0x369, 0x51C},
      "secoc_key_032_group": {0x032},
      "secoc_key_048_group": {0x048},
      "secoc_key_266_group": {0x266},
      "secoc_key_36f_group": {0x36F},
      "central_gateway_key": {0x370},
    }
    dbc = DBC("gm_global_b_supercruise1_secoc_bus2")
    actual_bus2: dict[str, set[int]] = {}
    for msg in dbc.msgs.values():
      if key_role := msg.attrs.get("SecOCKeyRole"):
        actual_bus2.setdefault(str(key_role), set()).add(msg.address)
    assert actual_bus2 == expected_bus2

    observed_family = {msg.address for msg in dbc.msgs.values()
                       if msg.attrs.get("SecOCObservedKeyFamily") == "shared_secoc_family_b"}
    assert observed_family == {0x02F, 0x032, 0x048, 0x0E2, 0x262, 0x266, 0x267, 0x36F, 0x516}

    candidates = "secoc_key_032_group,secoc_key_048_group,secoc_key_266_group,secoc_key_36f_group"
    ambiguous = {msg.address for msg in dbc.msgs.values() if msg.attrs.get("SecOCKeyCandidates") == candidates}
    assert ambiguous == {0x02F, 0x0E2, 0x262, 0x267, 0x516}

    for bus in (3, 5, 8):
      dbc = DBC(f"gm_global_b_supercruise1_secoc_bus{bus}")
      assert dbc.addr_to_msg[0x370].attrs["SecOCKeyRole"] == "central_gateway_key"

  def test_companion_schedule_cannot_drift_from_the_counter(self):
    # the schedule is read off the freshness counter itself, so an out-of-band signing of a
    # message sharing the freshness group cannot put the companion on the wrong tick
    period = GM_CATALOG[(2, 0x271)].companion.period
    auth = SecOcAuthenticator(GM_CATALOG, KEY)

    published = []
    for i in range(period * 3):
      if i == 5:  # something else advances the same counter behind secure()'s back
        auth.msg_cnt[(2, 0x271)] += 1
      for addr, data, _bus in auth.secure((0x271, bytes(8), 2)):
        if addr == 0x39C:
          published.append(struct.unpack("<I", data[:4])[0])

    assert len(published) >= 2
    assert {b - a for a, b in zip(published, published[1:], strict=False)} == {period + 1}
    assert all(v % (period + 1) == period for v in published), "still on the counter's own tick"

  def test_catalog_is_keyed_by_bus_and_address(self):
    # the same address on another bus is a different message, and 102 ids on this vehicle
    # carry a different length on a different bus
    assert (2, 0x271) in GM_CATALOG
    assert (8, 0x271) not in GM_CATALOG
    assert GM_CATALOG[(8, 0x021)].bus == 8
    assert GM_CATALOG.on_bus(3).buses == {3}

    duplicate = SecOcMessage(bus=2, addr=0x271, profile=GM_CATALOG[(2, 0x271)].profile, data_id=1, fv_id=0x271,
                             key_id="safety_control_key")
    with pytest.raises(ValueError, match="duplicate"):
      SecOcCatalog([*GM_CATALOG, duplicate])

  def test_port_catalog_binds_roles_to_the_brands_canbus(self):
    port = SUPERCRUISE1.port_catalog({Bus.pt: CanBus.POWERTRAIN})
    assert port.buses == {CanBus.POWERTRAIN}, "only vehicle buses the port reaches survive"
    assert len(port) == len(GM_CATALOG.on_bus(2))
    assert port[(CanBus.POWERTRAIN, 0x271)].companion == GM_CATALOG[(2, 0x271)].companion
    assert (2, 0x271) not in port, "vehicle numbering does not leak into the port catalog"

    auth = SecOcAuthenticator(port, KEY)
    ((_, _, bus),) = auth.secure((0x271, bytes(8), CanBus.POWERTRAIN))
    assert bus == CanBus.POWERTRAIN, "frames go out on the port's bus, not the vehicle's"

  def test_port_catalog_takes_any_offset_from_the_caller(self):
    # a multi-panda harness offsets the brand's constants; nothing here needs to know
    port = SUPERCRUISE1.port_catalog({Bus.pt: CanBus.POWERTRAIN + 4})
    assert port.buses == {CanBus.POWERTRAIN + 4}

  def test_port_catalog_drops_roles_the_port_does_not_reach(self):
    assert len(SUPERCRUISE1.port_catalog({})) == 0, "a port reaching no roles signs nothing"
    # a role the vehicle does not carry is not an error, it just binds nothing extra
    assert SUPERCRUISE1.port_catalog({Bus.pt: 0, Bus.cam: 2}).buses == {0}
    assert set(SUPERCRUISE1.bus_roles) <= GM_CATALOG.buses, "a roled bus must exist in the catalog"
