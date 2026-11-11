import msgpack
import pytest

from traffic_taffy.dissection import Dissection


def test_load_saved_with_tuple_keys(tmp_path) -> None:
    """Caches with tuple (array) dictionary keys must still be loadable."""
    cache = {
        "PCAP_DISSECTION_VERSION": Dissection.DISSECTION_VERSION,
        "file": "test.pcap",
        "parameters": {"bin_size": 1, "ignore_list": []},
        "dissection": {
            0: {
                "Ethernet_IP_UDP_DNS_an_text": {
                    ("name", "hostname.bind"): 3,
                    ("type", 16): 4,
                }
            }
        },
    }
    where = tmp_path / "test.pcap.taffy"
    where.write_bytes(msgpack.packb(cache))

    # confirm the plain loader really does fail on this content
    with pytest.raises(TypeError):
        msgpack.unpackb(where.read_bytes(), strict_map_key=False)

    dissection = Dissection("test.pcap")
    contents = dissection.load_saved(str(where), dont_overwrite=True)
    assert contents["dissection"][0]["Ethernet_IP_UDP_DNS_an_text"] == {
        ("name", "hostname.bind"): 3,
        ("type", 16): 4,
    }
