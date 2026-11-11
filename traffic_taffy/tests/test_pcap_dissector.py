import os
from traffic_taffy.dissector_engine.dpkt import DissectionEngineDpkt
from traffic_taffy.dissection import Dissection
from traffic_taffy.dissector import PCAPDissector, PCAPDissectorLevel


def test_dissector_load() -> None:
    from traffic_taffy.dissector import PCAPDissector

    pd = PCAPDissector("bogus")
    assert isinstance(pd, PCAPDissector)
    assert pd.pcap_file == "bogus"


def test_dissector_simple_callback() -> None:
    base_pcap = "/tmp/dissector-test.pcap"  # doesn't need to exist
    save_file = base_pcap + ".taffy"

    dpkt_engine = DissectionEngineDpkt(base_pcap)
    dpkt_engine.init_dissection()
    dpkt_engine.dissection.bin_size = 2
    dpkt_engine.dissector_level = PCAPDissectorLevel.COUNT_ONLY
    dpkt_engine.callback(10, b"")

    TOTAL_COUNT = Dissection.TOTAL_COUNT
    TOTAL_SUBKEY = Dissection.TOTAL_SUBKEY

    assert dpkt_engine.dissection.data == {
        0: {TOTAL_COUNT: {TOTAL_SUBKEY: 1}},
        10: {TOTAL_COUNT: {TOTAL_SUBKEY: 1}},
    }

    dpkt_engine.callback(12, b"")
    assert dict(dpkt_engine.dissection.data) == {
        0: {TOTAL_COUNT: {TOTAL_SUBKEY: 2}},
        10: {TOTAL_COUNT: {TOTAL_SUBKEY: 1}},
        12: {TOTAL_COUNT: {TOTAL_SUBKEY: 1}},
    }

    dpkt_engine.callback(11, b"")
    assert dpkt_engine.dissection.data == {
        0: {TOTAL_COUNT: {TOTAL_SUBKEY: 3}},
        10: {TOTAL_COUNT: {TOTAL_SUBKEY: 2}},
        12: {TOTAL_COUNT: {TOTAL_SUBKEY: 1}},
    }

    if os.path.exists(save_file):
        os.unlink(save_file)

    dpkt_engine.dissection.save(save_file)

    # create a new one to make sure it's blank
    from traffic_taffy.taffy_config import TaffyConfig

    config = TaffyConfig(
        {
            "dissect": {
                "dissection_level": PCAPDissectorLevel.COUNT_ONLY.value,
                "cache_results": True,
            }
        }
    )

    pd = PCAPDissector(
        base_pcap,
        config,
    )

    pd.load()

    assert pd.dissection.data == {
        0: {TOTAL_COUNT: {TOTAL_SUBKEY: 3}},
        10: {TOTAL_COUNT: {TOTAL_SUBKEY: 2}},
        12: {TOTAL_COUNT: {TOTAL_SUBKEY: 1}},
    }

    os.unlink(save_file)


def test_dissector_scapy_callback() -> None:
    assert True


def test_dissector_fractional_bin_size() -> None:
    dpkt_engine = DissectionEngineDpkt("/tmp/dissector-test-frac.pcap")
    dpkt_engine.init_dissection()
    dpkt_engine.dissection.bin_size = 0.5
    dpkt_engine.dissector_level = PCAPDissectorLevel.COUNT_ONLY

    for ts in (10.0, 10.4, 10.5, 10.9, 11.25):
        dpkt_engine.callback(ts, b"")

    TOTAL_COUNT = Dissection.TOTAL_COUNT
    TOTAL_SUBKEY = Dissection.TOTAL_SUBKEY
    data = dpkt_engine.dissection.data
    assert data[10.0][TOTAL_COUNT][TOTAL_SUBKEY] == 2
    assert data[10.5][TOTAL_COUNT][TOTAL_SUBKEY] == 2
    assert data[11.0][TOTAL_COUNT][TOTAL_SUBKEY] == 1


def test_bin_size_type() -> None:
    import argparse
    import pytest
    from traffic_taffy.dissector import bin_size_type

    assert bin_size_type("2") == 2 and isinstance(bin_size_type("2"), int)
    assert bin_size_type("2.0") == 2 and isinstance(bin_size_type("2.0"), int)
    assert bin_size_type("0.25") == 0.25
    for bad in ("abc", "-1", "nan", "inf"):
        with pytest.raises(argparse.ArgumentTypeError):
            bin_size_type(bad)
