import unittest
from opendbc.can import CANParser
from opendbc.can.dbc import DBC
from opendbc.can.tests import ALL_DBCS, TEST_DBC


class TestDBCParser(unittest.TestCase):
  def test_enough_dbcs(self):
    # sanity check that we're running on the real DBCs
    assert len(ALL_DBCS) > 20

  def test_parse_all_dbcs(self):
    """
      Dynamic DBC parser checks:
        - Checksum and counter length, start bit, endianness
        - Duplicate message addresses and names
        - Signal out of bounds
        - All BO_, SG_, VAL_ lines for syntax errors
    """

    for dbc in ALL_DBCS:
      with self.subTest(dbc=dbc):
        CANParser(dbc, [], 0)

  def test_message_transmitter(self):
    # the sender named on the BO_ line, kept verbatim: "XXX" and "Vector__XXX" mean unknown
    dbc = DBC(TEST_DBC)
    self.assertEqual(dbc.addr_to_msg[228].transmitter, "EON")
    self.assertEqual(dbc.addr_to_msg[316].transmitter, "XXX")

  def test_message_attributes(self):
    # BA_ lines on messages land in Msg.attrs as int, float or str; signal and global ones do not
    dbc = DBC(TEST_DBC)
    self.assertEqual(dbc.addr_to_msg[228].attrs, {"GenMsgCycleTime": 10, "SecOCKeyRole": "test_key", "Ratio": 0.5})
    self.assertEqual(dbc.addr_to_msg[316].attrs, {})
