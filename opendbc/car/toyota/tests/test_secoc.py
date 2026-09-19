import pytest

from opendbc.can.dbc import DBC
from opendbc.car import structs
from opendbc.car.car_helpers import interfaces
from opendbc.car.toyota.values import CAR
from opendbc.car.secoc import SecOcAuthenticator, authenticate, layout_from_dbc, truncated_mac
from opendbc.car.toyota.secoc import KEY_VEHICLE, TOYOTA_CATALOG, TOYOTA_SECOC, TOYOTA_SYNC, TOYOTA_SYNC_ID

KEY = bytes(range(16))

# (addr, trip_cnt, reset_cnt, msg_cnt, payload, expected) taken from the original hand-rolled
# implementation this replaced, so the profile cannot silently drift.
TOYOTA_VECTORS = [
  (0x2E4, 0xBB50, 0x54D4F, 681, "c4b89dc868ba37d9", "c4b89dc87f17a982"),
  (0x2E4, 0xCC27, 0x2174A, 712, "cece9f09b43ceb7e", "cece9f0922ee900b"),
  (0x2E4, 0x57A9, 0xA0A0F, 936, "8766221624d01b08", "8766221638485d2a"),
  (0x131, 0xFBB8, 0x6CC8C, 728, "a88d344e16fe9708", "a88d344e07b81b86"),
  (0x131, 0x4C20, 0x4BD81, 954, "29faea0a59625379", "29faea0a9c1449ea"),
  (0x131, 0x7215, 0x15A93, 902, "eccf9da00cdab434", "eccf9da0b0b4d211"),
  (0x183, 0xB9F2, 0xBE5AC, 66, "4a4a3774d1534567", "4a4a3774865eff6e"),
  (0x183, 0x87D4, 0xC5D92, 991, "ad23bf6e53f1892b", "ad23bf6eeb9ec749"),
  (0x183, 0x8FDE, 0xF7FF1, 525, "4d37684a534d1601", "4d37684a5285b952"),
]

# (trip_cnt, reset_cnt, id, expected)
TOYOTA_SYNC_VECTORS = [
  (0xB594, 0x67FF0, 0x2E4, 0x130669E),
  (0x8A9B, 0xB4132, 0x2E4, 0x674074D),
  (0x85EE, 0xCF45C, 0x2E4, 0xD3E463A),
  (0x492A, 0x5A06E, 0x001, 0x8689FEB),
  (0x06A1, 0x77289, 0x001, 0x4801B05),
]


class TestToyotaSecOc:
  @pytest.mark.parametrize("addr, trip, reset, cnt, payload, expected", TOYOTA_VECTORS)
  def test_known_vectors(self, addr, trip, reset, cnt, payload, expected):
    msg = TOYOTA_CATALOG[(0, addr)]
    _, out, _ = authenticate(KEY, msg, {'trip': trip, 'reset': reset, 'msg': cnt}, (addr, bytes.fromhex(payload), 0))
    assert out.hex() == expected

  @pytest.mark.parametrize("trip, reset, id_, expected", TOYOTA_SYNC_VECTORS)
  def test_sync_mac(self, trip, reset, id_, expected):
    assert truncated_mac(KEY, TOYOTA_SYNC, {'trip': trip, 'reset': reset, 'id': id_}) == expected

  def test_payload_is_preserved(self):
    # the authenticated payload bytes must survive untouched, the MAC only fills the tail
    payload = bytes.fromhex("deadbeefcafebabe")
    for msg in TOYOTA_CATALOG:
      addr = msg.addr
      _, out, _ = authenticate(KEY, msg, {'trip': 1, 'reset': 2, 'msg': 3}, (addr, payload, 0))
      assert out[: TOYOTA_SECOC.tail_offset] == payload[: TOYOTA_SECOC.tail_offset]

  def test_one_named_key_covers_everything(self):
    assert TOYOTA_CATALOG.key_ids == {KEY_VEHICLE}
    auth = SecOcAuthenticator(TOYOTA_CATALOG, sync_profile=TOYOTA_SYNC)
    assert auth.missing_keys == {KEY_VEHICLE}
    auth.keys = {KEY_VEHICLE: KEY}
    assert not auth.missing_keys
    auth.resynchronize(trip=0xB594, reset=0x67FF0)
    assert auth.verify_sync(0x130669E, key_id=KEY_VEHICLE, id=0x2E4)
    assert not auth.verify_sync(0x130669E, key_id=KEY_VEHICLE, id=TOYOTA_SYNC_ID)


class TestToyotaDbc:
  def test_dbc_reproduces_the_hardcoded_profile(self):
    dbc = DBC("toyota_secoc_pt_generated")
    for msg in TOYOTA_CATALOG:
      derived = layout_from_dbc(dbc.addr_to_msg[msg.addr], TOYOTA_SECOC.signals)
      assert derived == (TOYOTA_SECOC.tail_layout, TOYOTA_SECOC.tail_offset), f"{msg.addr:#05x}"


class TestCarController:
  """The port's wiring: the controller reads the car's sync frame into the authenticator, signs
  every SecOC frame it emits with its own counter, and restarts them when the car resets."""

  SIGNED = (0x2E4, 0x131, 0x183)  # STEERING_LKA every tick, STEERING_LTA_2 every 2nd, ACC_CONTROL_2 every 3rd

  @staticmethod
  def _interface():
    CarInterface = interfaces[CAR.TOYOTA_RAV4_PRIME]
    CP = CarInterface.get_params(CAR.TOYOTA_RAV4_PRIME, {bus: {} for bus in range(7)}, [], alpha_long=False, is_release=False, docs=False)
    return CarInterface(CP)

  @staticmethod
  def _sync(CS, trip, reset):
    CS.secoc_synchronization = {'TRIP_CNT': trip, 'RESET_CNT': reset,
                                'AUTHENTICATOR': truncated_mac(KEY, TOYOTA_SYNC, {'trip': trip, 'reset': reset, 'id': TOYOTA_SYNC_ID})}

  def _tick(self, CI, n):
    CC = structs.CarControl().as_reader()
    frames = []
    for _ in range(n):
      _, sends = CI.CC.update(CC, CI.CS, 0)
      frames.append([(addr, data) for addr, data, _ in sends if addr in self.SIGNED])
    return frames

  def test_the_old_single_key_attribute_fails_loudly(self):
    # a caller still assigning the pre-keystore attribute must not silently leave frames unsigned
    CI = self._interface()
    for obj in (CI.CC, CI.CS):
      with pytest.raises(AttributeError, match="secoc.load_keys"):
        obj.secoc_key = KEY
      with pytest.raises(AttributeError, match="secoc.load_keys"):
        obj.secoc_key  # noqa: B018

  def test_nothing_is_signed_without_a_key(self):
    CI = self._interface()
    assert CI.CC.secoc is not None and CI.CC.secoc.missing_keys == {KEY_VEHICLE}
    self._sync(CI.CS, 1, 2)
    (frames,) = self._tick(CI, 1)
    assert [addr for addr, _ in frames] == [0x2E4], "STEERING_LKA goes out unsigned, the SecOC-only frames are not sent"
    assert frames[0][1][4:] == bytes(4)
    assert CI.CC.secoc.msg_cnt == {}

  def test_frames_are_signed_with_a_counter_per_message(self):
    CI = self._interface()
    CI.CC.secoc.load_keys(KEY.hex())
    self._sync(CI.CS, 0xB594, 0x67FF0)

    seen = {addr: 0 for addr in self.SIGNED}
    for frames in self._tick(CI, 6):
      for addr, data in frames:
        msg = TOYOTA_CATALOG[(0, addr)]
        want = authenticate(KEY, msg, {'trip': 0xB594, 'reset': 0x67FF0, 'msg': seen[addr]}, (addr, data[:4] + bytes(4), 0))
        assert (addr, data, 0) == want, f"{addr:#x} frame {seen[addr]}"
        seen[addr] += 1
    assert seen == {0x2E4: 6, 0x131: 3, 0x183: 2}
    assert CI.CC.secoc.msg_cnt == {(0, addr): n for addr, n in seen.items()}

  def test_a_reset_restarts_the_counters(self):
    CI = self._interface()
    CI.CC.secoc.load_keys(KEY.hex())
    self._sync(CI.CS, 0xB594, 0x67FF0)
    self._tick(CI, 6)

    self._sync(CI.CS, 0xB594, 0x67FF1)
    (frames,) = self._tick(CI, 1)
    assert CI.CC.secoc.msg_cnt == {(0, 0x2E4): 1, (0, 0x131): 1, (0, 0x183): 1}
    for addr, data in frames:
      want = authenticate(KEY, TOYOTA_CATALOG[(0, addr)], {'trip': 0xB594, 'reset': 0x67FF1, 'msg': 0}, (addr, data[:4] + bytes(4), 0))
      assert (addr, data, 0) == want
