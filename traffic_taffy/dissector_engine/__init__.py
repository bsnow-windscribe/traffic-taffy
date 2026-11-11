"""Base class for a dissection engine with subclasses overriding load()"""

import math

from traffic_taffy.dissection import Dissection, PCAPDissectorLevel
from typing import List


class DissectionEngine:
    def __init__(
        self,
        pcap_file,
        pcap_filter: str = "",
        maximum_count: int = 0,
        bin_size: float = 0,
        dissector_level: PCAPDissectorLevel = PCAPDissectorLevel.COMMON_LAYERS,
        cache_file_suffix: str = "pkl",
        ignore_list: list = [],
        layers: List[str] | None = None,
    ):
        self.pcap_file = pcap_file
        self.dissector_level = dissector_level
        self.bin_size = bin_size
        self.maximum_count = maximum_count
        self.pcap_filter = pcap_filter
        self.cache_file_suffix = cache_file_suffix
        self.ignore_list = set(ignore_list)
        self.layers = layers

    def start_packet(
        self, timestamp: float, dissection: Dissection | None = None
    ) -> None:
        if not dissection:
            dissection = self.dissection

        # set and bin-ize the timestamp
        bin_size = dissection.bin_size
        if bin_size and bin_size != int(bin_size):
            # fractional bin sizes: keep sub-second precision, and round
            # away floating point noise (eg, 0.30000000000000004)
            dissection.timestamp = round(
                math.floor(float(timestamp) / bin_size) * bin_size, 6
            )
        else:
            dissection.timestamp = int(timestamp)
            if bin_size:
                dissection.timestamp = (
                    dissection.timestamp - dissection.timestamp % int(bin_size)
                )

        # increment the base counter for all packets
        dissection.incr(Dissection.TOTAL_COUNT, dissection.TOTAL_SUBKEY)

    def init_dissection(self) -> Dissection:
        self.dissection = Dissection(
            pcap_file=self.pcap_file,
            dissector_level=self.dissector_level,
            bin_size=self.bin_size,
            pcap_filter=self.pcap_filter,
            maximum_count=self.maximum_count,
            cache_file_suffix=self.cache_file_suffix,
            ignore_list=self.ignore_list,
        )
        return self.dissection

    def load(self) -> Dissection:
        """Load the capture file into memory."""
        self.init_dissection()
        self.load_data()
        self.dissection.calculate_metadata()
        return self.dissection

    def incr(self, name: str, value: str | int) -> None:
        if name not in self.ignore_list:
            self.dissection.incr(name, value)
