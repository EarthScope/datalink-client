# datalink-client

DataLink protocol client for reading and writing data using the DataLink protocol. DataLink is a simple, packet-based streaming protocol used in seismological data systems, primarily with EarthScope's [ringserver](https://github.com/earthscope/ringserver) software.

Requires Python 3.11+.

## Installation

```bash
pip install datalink-client
```

## Usage

### Sync API

```python
from datalink_client import DataLink

with DataLink("localhost", 16000) as dl:
    dl.match("FDSN:IU_COLA_.*")
    dl.stream()
    for packet in dl.collect():
        print(packet.streamid, len(packet.data))
```

### Async API

`AsyncDataLink` offers the same commands as `DataLink`, as coroutines, built on `asyncio`:

```python
import asyncio
from datalink_client import AsyncDataLink

async def main():
    async with AsyncDataLink("localhost", 16000) as dl:
        await dl.match("FDSN:IU_COLA_.*")
        await dl.stream()
        async for packet in dl.collect():
            print(packet.streamid, len(packet.data))

asyncio.run(main())
```

The [simpledali](https://github.com/crotwell/simpledali) package is another option for async/await support.

### Command-line client

An interactive client is available after install:

```bash
datalink-client [host:port]
```

Default is `localhost:16000`. Use `datalink-client --help` for options (timeout, TLS, auth).
