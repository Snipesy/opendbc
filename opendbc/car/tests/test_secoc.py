import pytest

from opendbc.can.dbc import Msg, Signal
from opendbc.car.secoc import (MAC, SecOcAuthenticator, SecOcCatalog, SecOcMessage, SecOcProfile, authenticate, format_keystore,
                              layout_from_dbc, parse_keystore, truncated_mac)

KEY = bytes(range(16))

# A minimal in-band scheme: 28 bit MAC trailing a 4 byte payload, 4 bits of counter beside it.
PROFILE = SecOcProfile(
  header_layout=(("data_id", 16),),
  freshness_layout=(("trip", 16), ("msg", 8)),
  tail_layout=(("msg", 4), (MAC, 28)),
  tail_offset=4,
)
SYNC = SecOcProfile(header_layout=(("id", 16),), freshness_layout=(("trip", 16),), tail_layout=((MAC, 28),))
CATALOG = SecOcCatalog(SecOcMessage(bus=0, addr=addr, profile=PROFILE, data_id=addr, fv_id=addr, key_id='k') for addr in (0x100, 0x200, 0x300))

# The signal aliases of an authenticator that leads the frame, with a status field beside the counter.
SIGNALS = ((MAC, "AUTHENTICATOR"), ("msg", "SECOC_FRESHNESS"), ("flags", "SECOC_AUX"))


def _sig(name, start_bit, size):
  return Signal(name=name, start_bit=start_bit, msb=0, lsb=0, size=size, is_signed=False, factor=1, offset=0, is_little_endian=False)


class TestLayoutFromDbc:
  """The DBC already says where the authenticator bits are, the same way it does for CHECKSUM
  and COUNTER. Only the signal names differ per platform, which the aliases carry."""

  def test_derives_a_leading_tail(self):
    # an authenticator leading the frame, with the truncated counter packed below it
    msg = Msg(
      name="ACP3_271",
      address=0x271,
      size=8,
      sigs={
        "AUTHENTICATOR": _sig("AUTHENTICATOR", 7, 27),  # bytes 0..2 plus the top 3 of byte 3
        "SECOC_FRESHNESS": _sig("SECOC_FRESHNESS", 28, 5),  # low 5 bits of byte 3
      },
    )
    assert layout_from_dbc(msg, SIGNALS[:2]) == (((MAC, 27), ("msg", 5)), 0)

  def test_derives_a_leading_tail_with_a_status_field(self):
    msg = Msg(
      name="ACP3_284",
      address=0x284,
      size=12,
      sigs={
        "AUTHENTICATOR": _sig("AUTHENTICATOR", 7, 32),  # bytes 0..3
        "SECOC_FRESHNESS": _sig("SECOC_FRESHNESS", 39, 5),  # byte 4, above the status bits
        "SECOC_AUX": _sig("SECOC_AUX", 34, 3),  # low 3 bits of byte 4
      },
    )
    assert layout_from_dbc(msg, SIGNALS) == (((MAC, 32), ("msg", 5), ("flags", 3)), 0)

  def test_rejects_a_missing_or_unnamed_authenticator(self):
    msg = Msg(name="X", address=1, size=8, sigs={"AUTHENTICATOR": _sig("AUTHENTICATOR", 7, 32)})
    with pytest.raises(ValueError, match="no signal named"):
      layout_from_dbc(msg, SIGNALS[:2])
    with pytest.raises(ValueError, match="nothing identifies the authenticator"):
      layout_from_dbc(msg, (("msg", "AUTHENTICATOR"),))

  def test_rejects_a_region_that_is_not_contiguous_and_byte_aligned(self):
    def msg(**sigs):
      return Msg(name="X", address=1, size=8, sigs={name: _sig(name, start, size) for name, (start, size) in sigs.items()})

    # bytes 0..2, then the low 5 bits of byte 3: the top 3 bits of byte 3 are unclaimed
    with pytest.raises(ValueError, match="gap"):
      layout_from_dbc(msg(AUTHENTICATOR=(7, 24), SECOC_FRESHNESS=(28, 5)), SIGNALS[:2])

    # the counter starts a bit inside the authenticator
    with pytest.raises(ValueError, match="overlaps"):
      layout_from_dbc(msg(AUTHENTICATOR=(7, 27), SECOC_FRESHNESS=(29, 4)), SIGNALS[:2])

    # an overlap and a gap of the same size cancel out in a total, and must still be refused
    with pytest.raises(ValueError, match="overlaps"):
      layout_from_dbc(msg(AUTHENTICATOR=(7, 16), SECOC_FRESHNESS=(15, 8), SECOC_AUX=(31, 8)), SIGNALS)

    # contiguous, but 31 bits
    with pytest.raises(ValueError, match="byte aligned"):
      layout_from_dbc(msg(AUTHENTICATOR=(7, 27), SECOC_FRESHNESS=(28, 4)), SIGNALS[:2])


class TestSecOcAuthenticator:
  def test_counters_are_per_freshness_id(self):
    auth = SecOcAuthenticator(CATALOG, KEY, sync_profile=SYNC)
    auth.resynchronize(trip=0x1234)
    for i in range(4):
      for msg in CATALOG:
        got = auth.secure((msg.addr, bytes(range(8)), 0))
        want = authenticate(KEY, msg, {'trip': 0x1234, 'msg': i}, (msg.addr, bytes(range(8)), 0))
        assert got == [want], "in-band freshness: the secured frame alone"

  def test_resynchronize_resets_counters(self):
    auth = SecOcAuthenticator(CATALOG, KEY, sync_profile=SYNC)
    assert auth.resynchronize(trip=5)
    auth.secure((0x100, bytes(8), 0))
    assert auth.msg_cnt == {(0, 0x100): 1}

    assert not auth.resynchronize(trip=5)
    assert auth.msg_cnt == {(0, 0x100): 1}

    assert auth.resynchronize(trip=6)
    assert auth.msg_cnt == {}

  def test_verify_sync_rejects_wrong_key(self):
    auth = SecOcAuthenticator(CATALOG, KEY, sync_profile=SYNC)
    auth.resynchronize(trip=0x1234)
    sync = {'trip': 0x1234, 'id': 0xF}
    assert auth.verify_sync(truncated_mac(KEY, SYNC, sync), key_id='k', id=0xF)
    assert not auth.verify_sync(truncated_mac(bytes(16), SYNC, sync), key_id='k', id=0xF)

  def test_verify_sync_needs_a_sync_profile(self):
    auth = SecOcAuthenticator(CATALOG, KEY)
    with pytest.raises(ValueError, match="no synchronization message"):
      auth.verify_sync(0, key_id='k')

  def test_missing_key_is_named(self):
    auth = SecOcAuthenticator(CATALOG)
    with pytest.raises(KeyError, match="no key 'k'"):
      auth.secure((0x100, bytes(8), 0))

  def test_missing_keys_tracks_the_catalog(self):
    # keys arrive at runtime, after construction; the port signs once nothing is missing
    two = SecOcCatalog([
      SecOcMessage(bus=0, addr=0x100, profile=PROFILE, data_id=0x100, fv_id=0x100, key_id='a'),
      SecOcMessage(bus=0, addr=0x200, profile=PROFILE, data_id=0x200, fv_id=0x200, key_id='b'),
    ])
    auth = SecOcAuthenticator(two)
    assert auth.missing_keys == {'a', 'b'}
    auth.keys = {'a': KEY, 'c': KEY}
    assert auth.missing_keys == {'b'}, "material for an id the catalog does not name is not credited"
    auth.keys = {'a': KEY, 'b': bytes(16)}
    assert auth.missing_keys == set()
    assert auth.secure((0x100, bytes(8), 0)) == [authenticate(KEY, two[(0, 0x100)], {'msg': 0}, (0x100, bytes(8), 0))]
    assert auth.secure((0x200, bytes(8), 0)) == [authenticate(bytes(16), two[(0, 0x200)], {'msg': 0}, (0x200, bytes(8), 0))]

  def test_one_key_serves_every_id(self):
    assert SecOcAuthenticator(CATALOG, KEY).keys == {'k': KEY}

  def test_load_and_dump_keys_round_trip(self):
    auth = SecOcAuthenticator(CATALOG)
    auth.load_keys('{"k": "%s", "spare": "%s"}' % (KEY.hex(), bytes(16).hex()))
    assert auth.keys == {'k': KEY, 'spare': bytes(16)}
    assert not auth.missing_keys

    other = SecOcAuthenticator(CATALOG)
    other.load_keys(auth.dump_keys())
    assert other.keys == auth.keys

  def test_load_keys_takes_the_bare_key_of_a_single_key_scheme(self):
    # the stored form that predates named keys, bound to the catalog's one id
    auth = SecOcAuthenticator(CATALOG)
    auth.load_keys(KEY.hex())
    assert auth.keys == {'k': KEY}
    auth.load_keys(KEY.hex().encode())
    assert auth.keys == {'k': KEY}


class TestKeystore:
  def test_stored_form_is_a_sorted_map_of_hex(self):
    assert format_keystore({'b': bytes(16), 'a': KEY}) == '{"a": "%s", "b": "%s"}' % (KEY.hex(), bytes(16).hex())

  def test_ids_the_catalog_does_not_name_are_kept(self):
    assert parse_keystore('{"other": "%s"}' % KEY.hex(), key_ids={'k'}) == {'other': KEY}

  def test_a_bare_key_needs_exactly_one_id(self):
    with pytest.raises(ValueError, match="exactly one key id"):
      parse_keystore(KEY.hex(), key_ids=set())
    with pytest.raises(ValueError, match="exactly one key id"):
      parse_keystore(KEY.hex(), key_ids={'a', 'b'})

  def test_rejects_malformed_material(self):
    with pytest.raises(ValueError, match="not hex"):
      parse_keystore('{"k": "zz"}')
    with pytest.raises(ValueError, match="15 bytes"):
      parse_keystore('{"k": "%s"}' % bytes(15).hex())
    with pytest.raises(ValueError, match="15 bytes"):
      parse_keystore(bytes(15).hex(), key_ids={'k'})
    with pytest.raises(ValueError, match="JSON object"):
      parse_keystore('{"k": 1}')
    with pytest.raises(ValueError, match="JSON object"):
      parse_keystore('{"k": {"nested": "00"}}')

  def test_every_aes_key_size_is_accepted(self):
    for size in (16, 24, 32):
      assert parse_keystore(bytes(size).hex(), key_ids={'k'}) == {'k': bytes(size)}


class TestProfiles:
  def test_freshness_layout_must_be_byte_aligned(self):
    profile = SecOcProfile(header_layout=(("data_id", 16),), freshness_layout=(("msg", 12),), tail_layout=((MAC, 24),))
    msg = SecOcMessage(bus=0, addr=0x123, profile=profile, data_id=0x123, fv_id=0, key_id='k')
    with pytest.raises(ValueError, match="byte aligned"):
      authenticate(KEY, msg, {}, (0x123, bytes(8), 0))

  def test_data_id_can_differ_from_address(self):
    # schemes that assign a Data ID independent of the CAN address must not collide
    a = SecOcMessage(bus=0, addr=0x2E4, profile=PROFILE, data_id=0x0042, fv_id=0, key_id='k')
    b = SecOcMessage(bus=0, addr=0x2E4, profile=PROFILE, data_id=0x0043, fv_id=0, key_id='k')
    ctx = {'trip': 1, 'msg': 3}
    assert authenticate(KEY, a, ctx, (0x2E4, bytes(8), 0)) != authenticate(KEY, b, ctx, (0x2E4, bytes(8), 0))

  def test_header_can_be_omitted(self):
    profile = SecOcProfile(header_layout=(), freshness_layout=(("msg", 16),), tail_layout=((MAC, 32),), tail_offset=4)
    msg = SecOcMessage(bus=0, addr=0x123, profile=profile, data_id=0, fv_id=0, key_id='k')
    _, out, _ = authenticate(KEY, msg, {'msg': 7}, (0x123, bytes(8), 0))
    assert out == bytes.fromhex("000000004ccb84b9")

  def test_mac_truncation(self):
    expected = {24: 0x6903CF, 28: 0x6903CFE, 32: 0x6903CFE3}
    for bits, want in expected.items():
      profile = SecOcProfile(header_layout=(("id", 16),), freshness_layout=(("trip", 16),), tail_layout=((MAC, bits),))
      assert truncated_mac(KEY, profile, {"id": 0xF, "trip": 1}) == want

  def test_a_layout_may_name_a_counter_twice(self):
    # a field is the counter masked to its width, so the truncated copy beside the full one
    # needs no name of its own
    twice = SecOcProfile(header_layout=(), freshness_layout=(("reset", 20), ("reset", 4)), tail_layout=((MAC, 32),))
    explicit = SecOcProfile(header_layout=(), freshness_layout=(("reset", 20), ("flag", 4)), tail_layout=((MAC, 32),))
    assert truncated_mac(KEY, twice, {"reset": 0xABCDE}) == truncated_mac(KEY, explicit, {"reset": 0xABCDE, "flag": 0xE})
    assert truncated_mac(KEY, twice, {"reset": 0xABCDE}) != truncated_mac(KEY, explicit, {"reset": 0xABCDE, "flag": 0})

  def test_tail_must_name_the_mac(self):
    with pytest.raises(ValueError, match="no 'mac' field"):
      SecOcProfile(header_layout=(), freshness_layout=(), tail_layout=(("msg", 8),))

  def test_tail_must_be_byte_aligned_to_frame(self):
    # a sync profile's tail is never framed, so the check is on signing rather than construction
    msg = SecOcMessage(bus=0, addr=1, profile=SYNC, data_id=1, fv_id=1, key_id='k')
    assert truncated_mac(KEY, SYNC, {}) < (1 << 28)
    with pytest.raises(ValueError, match="byte aligned"):
      authenticate(KEY, msg, {}, (1, bytes(8), 0))

  def test_a_frame_too_short_for_the_tail_is_refused(self):
    # a tail leading the frame needs a payload after it; one trailing needs the frame to reach it
    profile = SecOcProfile(header_layout=(), freshness_layout=(("msg", 8),), tail_layout=((MAC, 32),))
    leading = SecOcMessage(bus=0, addr=1, profile=profile, data_id=1, fv_id=1, key_id='k')
    with pytest.raises(ValueError, match="too short"):
      authenticate(KEY, leading, {}, (1, bytes(4), 0))
    assert len(authenticate(KEY, leading, {}, (1, bytes(5), 0))[1]) == 5

    trailing = CATALOG[(0, 0x100)]
    with pytest.raises(ValueError, match="too short"):
      authenticate(KEY, trailing, {}, (0x100, bytes(7), 0))
    assert len(authenticate(KEY, trailing, {}, (0x100, bytes(8), 0))[1]) == 8
