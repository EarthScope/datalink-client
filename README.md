# datalink-client

DataLink protocol 1.1 client for reading and writing data using the DataLink protocol. DataLink is a simple, packet-based streaming protocol used in seismological data systems, primarily with EarthScope's [ringserver](https://github.com/earthscope/ringserver) software.

## Installation

```bash
pip install datalink-client
```

## Usage

### Python API

```python
from datalink_client import DataLink

with DataLink("localhost", 16000) as dl:
    dl.match("FDSN:IU_COLA_.*")
    dl.position_set("LATEST", 0)
    dl.stream()
    for packet in dl.collect():
        print(packet.streamid, len(packet.data))
```

### Command-line client

An interactive client is available after install:

```bash
datalink-client [host:port]
```

Default is `localhost:16000`. Use `datalink-client --help` for options (timeout, TLS, auth).

## Async usage

This package provides a synchronous client. For async/await support (e.g. with asyncio), use the [simpledali](https://github.com/crotwell/simpledali) package.
