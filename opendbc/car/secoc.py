import json
import struct
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, replace

from Crypto.Hash import CMAC
from Crypto.Cipher import AES

# A field of a bit-packed record: (name, width in bits). Packed MSB first.
# Values come from the context, masked to the field's width, so a name may appear more than
# once at different widths; anything not in the context packs as zero.
Layout = tuple[tuple[str, int], ...]

# The counters and ids a MAC input is built from, keyed by the names the layouts use.
Context = dict[str, int]

CanMsg = tuple[int, bytes, int]

# Name of the authenticator field in a tail layout, and in a profile's signal aliases.
MAC = 'mac'


def _bits(layout: Layout) -> int:
  return sum(w for _, w in layout)


def _pack_bits(layout: Layout, ctx: Context) -> int:
  acc = 0
  for name, bits in layout:
    acc = (acc << bits) | (ctx.get(name, 0) & ((1 << bits) - 1))
  return acc


def _unpack_bits(layout: Layout, value: int) -> Context:
  fields, offset = {}, _bits(layout)
  for name, bits in layout:
    offset -= bits
    fields[name] = (value >> offset) & ((1 << bits) - 1)
  return fields


def _to_bytes(layout: Layout, ctx: Context) -> bytes:
  bits = _bits(layout)
  if bits % 8:
    raise ValueError(f"layout must be byte aligned, got {bits} bits")
  return _pack_bits(layout, ctx).to_bytes(bits // 8, 'big')


def aes_cmac(key: bytes, data: bytes) -> bytes:
  cmac = CMAC.new(key, ciphermod=AES)
  cmac.update(data)
  return cmac.digest()


def _frame_pos(sig) -> int:
  """How far a signal's most significant bit sits from the start of the frame, in bits."""
  if sig.is_little_endian:
    raise ValueError(f"{sig.name}: authenticator fields are big endian")
  return (sig.start_bit // 8) * 8 + (7 - sig.start_bit % 8)


def layout_from_dbc(msg, signals: tuple[tuple[str, str], ...]) -> tuple[Layout, int]:
  """Read a secured message's authenticator region off the DBC signals that name it.

  The DBC already says where the bits are, the same way it does for CHECKSUM and COUNTER; only
  the signal names differ per platform, which is what the aliases carry. What the DBC cannot
  say stays in Python: how the freshness is composed, which MAC function signs it, which key,
  and which companion frame publishes the counter.

  Returns the tail layout in frame order and its byte offset in the frame.
  """
  aliases = dict(signals)
  if MAC not in aliases:
    raise ValueError(f"{msg.name}: no {MAC!r} alias, nothing identifies the authenticator")

  found = []
  for canonical, sig_name in aliases.items():
    sig = msg.sigs.get(sig_name)
    if sig is None:
      raise ValueError(f"{msg.name}: no signal named {sig_name!r} for {canonical!r}")
    found.append((_frame_pos(sig), canonical, sig.size))
  found.sort()

  start = end = found[0][0]
  for pos, canonical, size in found:
    if pos != end:
      raise ValueError(f"{msg.name}: {canonical!r} leaves a gap or overlaps the field before it")
    end = pos + size
  if start % 8 or end % 8:
    raise ValueError(f"{msg.name}: authenticator region is not byte aligned")

  return tuple((canonical, size) for _, canonical, size in found), start // 8


@dataclass(frozen=True)
class SecOcProfile:
  """One message authentication scheme.

  The MAC is taken over [header][payload][freshness], or [header][freshness][payload] when
  freshness_before_payload is set. The frame carries the tail, the authenticator with any
  truncated freshness and status bits beside it, at tail_offset; the payload is everything
  outside the tail.

  A scheme's synchronization message, if it has one, is described by a profile of its own:
  it is the same construction with no payload.
  """
  # bit fields packed ahead of everything else in the MAC input, e.g. a data id and the address
  header_layout: Layout
  # the full freshness value fed to the MAC
  freshness_layout: Layout
  # the authenticator region in frame order: the MAC under the name MAC, truncated to that
  # width from the top of the full MAC, and the wire fields beside it
  tail_layout: Layout
  # byte offset of the tail in the frame
  tail_offset: int = 0
  freshness_before_payload: bool = False
  mac_fn: Callable[[bytes, bytes], bytes] = aes_cmac
  # DBC signal name for each tail field, keyed by the name the layout uses. layout_from_dbc()
  # reads the bit positions back out through these.
  signals: tuple[tuple[str, str], ...] = ()

  def __post_init__(self):
    if MAC not in dict(self.tail_layout):
      raise ValueError(f"tail layout has no {MAC!r} field")

  @property
  def mac_bits(self) -> int:
    return dict(self.tail_layout)[MAC]

  @property
  def tail_len(self) -> int:
    return _bits(self.tail_layout) // 8


@dataclass(frozen=True)
class Companion:
  """The clear-text frame publishing a secured message's full freshness value."""
  addr: int
  size: int
  # transmitted once every this many secured frames
  period: int = 1

  def frame(self, freshness: int, bus: int) -> CanMsg:
    return (self.addr, struct.pack('<I', freshness & 0xFFFFFFFF).ljust(self.size, b'\x00'), bus)


@dataclass(frozen=True)
class SecOcMessage:
  """One secured PDU, identified by the bus it lives on as well as its address.

  A CAN address is only unique within a bus: the same id routinely carries a different message,
  with a different length, on another bus. Keys bind to a frame on a bus, not to the module
  that sends it, so one sender's frames may be signed by several different keys and the same
  address on two buses may be signed by two.
  """
  bus: int
  addr: int
  profile: SecOcProfile
  # value of the header's data id field. Toyota uses the address, GM a constant 1
  data_id: int
  # messages sharing a freshness id share a counter, within a bus
  fv_id: int
  # which key signs this frame on this bus. A name for what the key covers, such as 'vehicle'
  # or 'ipm', never a storage slot: the catalog binds frames to names, a keystore binds names
  # to material, and only the latter differs per car
  key_id: str
  # the frame publishing this message's full freshness, when the scheme has one
  companion: Companion | None = None

  @property
  def ref(self) -> tuple[int, int]:
    return (self.bus, self.addr)


class SecOcCatalog:
  """Every secured PDU known for a platform, indexed by (bus, address)."""

  def __init__(self, messages: Iterable[SecOcMessage]):
    self._messages: dict[tuple[int, int], SecOcMessage] = {}
    for msg in messages:
      if msg.ref in self._messages:
        raise ValueError(f"duplicate entry for bus {msg.bus} address {msg.addr:#x}")
      self._messages[msg.ref] = msg

  def __getitem__(self, ref: tuple[int, int]) -> SecOcMessage:
    return self._messages[ref]

  def __contains__(self, ref: object) -> bool:
    return ref in self._messages

  def __iter__(self) -> Iterator[SecOcMessage]:
    return iter(self._messages.values())

  def __len__(self) -> int:
    return len(self._messages)

  @property
  def buses(self) -> set[int]:
    return {m.bus for m in self}

  @property
  def key_ids(self) -> set[str]:
    return {m.key_id for m in self}

  def on_bus(self, bus: int) -> 'SecOcCatalog':
    return SecOcCatalog(m for m in self if m.bus == bus)

  def rebus(self, bus_map: dict[int, int]) -> 'SecOcCatalog':
    """Re-index onto another bus numbering, dropping buses the map does not mention.

    Vehicle bus numbers and the bus indices a car port transmits on are different namespaces:
    this catalog speaks the vehicle's, a CarController speaks its own. Binding one to the
    other is explicit so the two can never be silently conflated.
    """
    return SecOcCatalog(replace(m, bus=bus_map[m.bus]) for m in self if m.bus in bus_map)


# AES-128, -192 and -256
KEY_SIZES = (16, 24, 32)


def parse_keystore(stored: str | bytes, key_ids: Iterable[str] = ()) -> dict[str, bytes]:
  """Decode a stored keystore into key material.

  The stored form is one JSON object from key id to hex, such as {"vehicle": "00..ff"}, so a
  car is either fully provisioned or not: there is no half state where one frame can be signed
  and another cannot. Ids the catalog does not name are kept, since a later port may need them;
  missing_keys is what says whether a port is ready.

  A bare hex string is the form that predates named keys. It holds the one key of a
  single-key scheme, and is bound to that scheme's id when key_ids names exactly one.
  """
  text = stored.decode() if isinstance(stored, bytes) else stored
  text = text.strip()
  if text.startswith('{'):
    raw = json.loads(text)
    if not isinstance(raw, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in raw.items()):
      raise ValueError("keystore must be a JSON object from key id to hex")
  else:
    ids = set(key_ids)
    if len(ids) != 1:
      raise ValueError(f"a bare key needs exactly one key id to bind to, got {sorted(ids)}")
    raw = {ids.pop(): text}

  keys = {}
  for key_id, hexed in raw.items():
    try:
      key = bytes.fromhex(hexed)
    except ValueError:
      raise ValueError(f"key {key_id!r} is not hex") from None
    if len(key) not in KEY_SIZES:
      raise ValueError(f"key {key_id!r} is {len(key)} bytes, expected one of {KEY_SIZES}")
    keys[key_id] = key
  return keys


def format_keystore(keys: dict[str, bytes]) -> str:
  """The stored form of a keystore, the inverse of parse_keystore()."""
  return json.dumps({key_id: key.hex() for key_id, key in sorted(keys.items())})


def truncated_mac(key: bytes, profile: SecOcProfile, ctx: Context, payload: bytes = b'') -> int:
  """The profile's MAC over the context and payload, truncated to the bits it keeps."""
  header = _to_bytes(profile.header_layout, ctx)
  freshness = _to_bytes(profile.freshness_layout, ctx)
  to_auth = header + (freshness + payload if profile.freshness_before_payload else payload + freshness)

  full_mac = profile.mac_fn(key, to_auth)
  return int.from_bytes(full_mac, 'big') >> (8 * len(full_mac) - profile.mac_bits)


def authenticate(key: bytes, msg: SecOcMessage, ctx: Context, can_msg: CanMsg) -> CanMsg:
  """The secured frame: the packer's frame with its tail filled in.

  The context carries the counters the scheme's layouts name, such as the per-message counter
  under 'msg'. The address and data id are added here. Tail fields the context does not name,
  such as status bits the packer set beside the truncated counter, are kept from the frame.
  """
  addr, data, bus = can_msg
  p = msg.profile
  start, stop = p.tail_offset, p.tail_offset + p.tail_len
  payload = data[:start] + data[stop:]
  if len(data) < stop or not payload:
    raise ValueError(f"{addr:#x} on bus {bus}: {len(data)} byte frame is too short for a tail at bytes {start}..{stop} and a payload")

  mac = truncated_mac(key, p, ctx | {'addr': addr, 'data_id': msg.data_id}, payload)
  packed = _unpack_bits(p.tail_layout, int.from_bytes(data[start:stop], 'big'))
  tail = _to_bytes(p.tail_layout, packed | ctx | {MAC: mac})
  return (addr, data[:start] + tail + data[stop:], bus)


class SecOcAuthenticator:
  """Signs a catalog's messages, holding one key per key id and one counter per freshness id.

  Keys are per frame per bus rather than per module, so the keystore is indexed by the key ids
  the catalog's entries name. Material is supplied at runtime, through load_keys() from its
  stored form or by assigning `keys`, and a port is ready to sign once `missing_keys` is
  empty. A single key may be passed instead for a scheme that has one.

  The context is whatever the car broadcasts that the scheme's layouts name, such as Toyota's
  trip and reset counters. It is adopted through resynchronize() and applies to every message;
  the per-message counter under 'msg' is this class's own.
  """

  def __init__(self, catalog: SecOcCatalog, keys: dict[str, bytes] | bytes | None = None,
               sync_profile: SecOcProfile | None = None):
    self.catalog = catalog
    self.sync_profile = sync_profile
    self.keys: dict[str, bytes] = {}
    if isinstance(keys, bytes):
      self.keys = dict.fromkeys(catalog.key_ids, keys)
    elif keys:
      self.keys = dict(keys)

    self.ctx: Context = {}
    self.msg_cnt: dict[tuple[int, int], int] = {}

  @property
  def missing_keys(self) -> set[str]:
    """Key ids the catalog names that no material has been supplied for."""
    return self.catalog.key_ids - self.keys.keys()

  def load_keys(self, stored: str | bytes) -> None:
    """Take the keystore in its stored form; see parse_keystore()."""
    self.keys = parse_keystore(stored, self.catalog.key_ids)

  def dump_keys(self) -> str:
    return format_keystore(self.keys)

  def key(self, key_id: str) -> bytes:
    try:
      return self.keys[key_id]
    except KeyError:
      raise KeyError(f"no key {key_id!r}") from None

  def _fv(self, msg: SecOcMessage) -> tuple[int, int]:
    # freshness ids are only unique within a bus
    return (msg.bus, msg.fv_id)

  def resynchronize(self, **ctx: int) -> bool:
    """Adopt the counters the car broadcasts, e.g. resynchronize(trip=..., reset=...).

    Returns True when they moved, in which case every per-message counter was rolled over:
    the message counter only means anything relative to the freshness it is combined with.
    """
    changed = ctx != self.ctx
    self.ctx = ctx
    if changed:
      self.msg_cnt = {}
    return changed

  def observe_freshness(self, ref: tuple[int, int], freshness: int) -> None:
    """Slave a freshness counter to a value seen on the bus.

    The next frame goes out on the tick after the observed one, never on or before it, so a
    sender coming up mid-drive cannot replay. A stale reading never rewinds the counter.
    """
    fv = self._fv(self.catalog[ref])
    self.msg_cnt[fv] = max(self.msg_cnt.get(fv, 0), freshness + 1)

  def verify_sync(self, authenticator: int, *, key_id: str, **fields: int) -> bool:
    """Check the car's synchronization MAC against the adopted context and the given fields."""
    if self.sync_profile is None:
      raise ValueError("this scheme has no synchronization message")
    return truncated_mac(self.key(key_id), self.sync_profile, self.ctx | fields) == authenticator

  def _sign(self, msg: SecOcMessage, can_msg: CanMsg) -> CanMsg:
    fv = self._fv(msg)
    cnt = self.msg_cnt.get(fv, 0)
    out = authenticate(self.key(msg.key_id), msg, self.ctx | {'msg': cnt}, can_msg)
    self.msg_cnt[fv] = cnt + 1
    return out

  def secure(self, can_msg: CanMsg) -> list[CanMsg]:
    """Every frame the scheme requires on the wire: the secured frame plus any companion.

    A scheme that carries its freshness in-band yields the secured frame alone. One with a
    companion cannot be transmitted without it: on its own the receiver never learns the
    freshness, so the frame is unverifiable.

    The companion consumes a counter tick of its own: the counter advances once per frame
    transmitted, secured or companion. So a run reads ... secured N-1, companion N, secured
    N+1 ..., and the counter steps by period + 1 between consecutive companions.

    Which tick the companion falls on is read off that counter rather than off a separate tally
    of frames sent, so nothing can drift out of step with it. The sender observed on the wire
    picks a different residue of its own, which is equally valid: all a receiver needs is the
    companion every period + 1 ticks.
    """
    addr, _, bus = can_msg
    msg = self.catalog[(bus, addr)]
    fv = self._fv(msg)

    frames = [self._sign(msg, can_msg)]
    c = msg.companion
    if c is not None and self.msg_cnt[fv] % (c.period + 1) == c.period:
      frames.append(c.frame(self.msg_cnt[fv], bus))
      self.msg_cnt[fv] += 1
    return frames
