"""
DataLink protocol 1.1 client for reading and writing data using the DataLink protocol.

DataLink is a simple, packet-based streaming protocol used in some seismological
data systems, primarily with EarthScope's ringserver software.

Quick start::

    from datalink_client import DataLink

    with DataLink("localhost", 16000) as dl:
        dl.match("FDSN:IU_COLA_.*")
        dl.set_position_latest()
        dl.stream()
        for packet in dl.collect():
            print(packet.streamid, len(packet.data))

Async quick start (requires Python 3.11+, same API as coroutines)::

    import asyncio
    from datalink_client import AsyncDataLink

    async def main():
        async with AsyncDataLink("localhost", 16000) as dl:
            await dl.match("FDSN:IU_COLA_.*")
            await dl.set_position_latest()
            await dl.stream()
            async for packet in dl.collect():
                print(packet.streamid, len(packet.data))

    asyncio.run(main())

Interactive client::

    datalink-client [host:port]
"""

from typing import TYPE_CHECKING

from .cli import main
from .client import DataLink
from .protocol import DataLinkError, DataLinkPacket, DataLinkResponse, DataLinkTimeout
from .time_utils import timestring_to_ustime, ustime_to_timestring

if TYPE_CHECKING:
    # Only for type checkers/IDEs; the real (lazy) import is in __getattr__
    # below, so importing datalink_client doesn't pull in asyncio unless
    # AsyncDataLink is actually used.
    from .aio import AsyncDataLink

__version__ = "1.5.1"
__all__ = [
    "AsyncDataLink",
    "DataLink",
    "DataLinkError",
    "DataLinkPacket",
    "DataLinkResponse",
    "DataLinkTimeout",
    "main",
    "timestring_to_ustime",
    "ustime_to_timestring",
]


def __getattr__(name: str):
    if name == "AsyncDataLink":
        from .aio import AsyncDataLink

        return AsyncDataLink
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
