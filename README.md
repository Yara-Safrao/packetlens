# PacketLens

A command-line tool that reads a `.pcap` file and explains the network traffic in plain language.

> **Status:** early development. Only the features under "Current features" exist today.

## Current features

- Protocol summary (TCP, UDP, other)
- DNS queries, with a warning for domain names that look randomly generated
- Most frequent TCP connections, with a note for unencrypted HTTP (port 80)

## Limitations

- The DNS check is a heuristic based on entropy. It can produce false positives (e.g. CDNs) and false negatives. It flags suspicions, it does not prove anything.
- HTTPS traffic appears as connections on port 443, but its content is encrypted and is not analysed.
- The whole file is loaded into memory, so very large captures are not supported yet.

## Roadmap

- [ ] Stream large files with `PcapReader`
- [ ] HTTP request summary
- [ ] Export report to a file
- [ ] More detection heuristics

## Usage

Requires Python 3.12+.

```
python3 -m venv .venv
source .venv/bin/activate
pip install scapy
python samples/make_sample.py
python -m src.packetlens.cli samples/demo.pcap
```

## Sample data

`samples/make_sample.py` generates a synthetic capture (`demo.pcap`) without touching the network. No real traffic is included.

## License

MIT