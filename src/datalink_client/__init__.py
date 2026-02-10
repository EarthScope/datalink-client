"""
DataLink protocol 1.1 client for reading and writing data using the DataLink protocol.

DataLink is a simple, packet-based streaming protocol used in some seismological
data systems, primarily with EarthScope's ringserver software.

Quick start::

    from datalink_client import DataLink

    with DataLink("localhost", 16000) as dl:
        dl.match("FDSN:IU_COLA_.*")
        dl.position_set("LATEST", 0)
        dl.stream()
        for packet in dl.collect():
            print(packet.streamid, len(packet.data))

Interactive client::

    datalink-client [host:port]
"""

from .client import DataLink
from .cli import main
from .protocol import DataLinkError, DataLinkPacket, DataLinkResponse
from .time_utils import timestring_to_ustime, ustime_to_timestring

__version__ = "1.1.1"
__all__ = [
    "DataLink",
    "DataLinkError",
    "DataLinkPacket",
    "DataLinkResponse",
    "main",
    "timestring_to_ustime",
    "ustime_to_timestring",
]
