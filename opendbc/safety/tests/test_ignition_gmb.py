import unittest

from opendbc.safety.tests.libsafety import libsafety_py as api

api.ffi.cdef('extern uint32_t ignition_can_cnt;')


class TestGmGlobalBIgnition(unittest.TestCase):
  def setUp(self):
    self.safety = api.libsafety
    self.safety.init_tests()
    self.safety.ignition_can_cnt = 3

  def receive(self, mode, freshness, bus=0, length=6, extended=False):
    data = bytearray(length)
    data[3] = freshness & 31
    data[4] = mode << 5  # PowerModeGate=0 is valid while driving.
    msg = api.make_CANPacket(0x370, bus, bytes(data))
    msg.extended = extended
    self.safety.ignition_can_hook(msg)

  def test_power_modes_and_off_debounce(self):
    for mode in (1, 2, 3, 4):
      self.setUp()
      self.receive(mode, 0)
      self.assertFalse(self.safety.get_ignition_can())
      self.receive(mode, 1)
      self.assertTrue(self.safety.get_ignition_can())
      for freshness in (2, 3, 4):
        self.receive(0, freshness)
        self.assertTrue(self.safety.get_ignition_can())
      self.receive(0, 5)
      self.assertFalse(self.safety.get_ignition_can())

  def test_duplicate_does_not_wake_or_refresh(self):
    self.receive(4, 1)
    self.receive(4, 1)
    self.assertFalse(self.safety.get_ignition_can())
    self.safety.ignition_can_cnt = 1
    self.receive(4, 1)
    self.assertEqual(self.safety.ignition_can_cnt, 1)

  def test_wrong_bus_length_extended_and_undefined(self):
    for kwargs in ({'bus': 1}, {'bus': 2}, {'length': 5}, {'length': 8}, {'extended': True}):
      self.setUp()
      self.receive(4, 1, **kwargs)
      self.receive(4, 2, **kwargs)
      self.assertFalse(self.safety.get_ignition_can())
    for mode in (5, 6, 7):
      self.receive(mode, 1)
      self.receive(mode, 2)
      self.assertFalse(self.safety.get_ignition_can())
      self.assertEqual(self.safety.ignition_can_cnt, 3)

  def test_wrap_and_timeout_reacquisition(self):
    self.receive(4, 31)
    self.receive(4, 0)
    self.assertTrue(self.safety.get_ignition_can())
    self.safety.init_tests()
    self.safety.ignition_can_cnt = 3
    self.receive(4, 1)
    self.assertFalse(self.safety.get_ignition_can())
    self.receive(4, 2)
    self.assertTrue(self.safety.get_ignition_can())
