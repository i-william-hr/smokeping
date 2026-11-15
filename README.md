# smokeping — latency graphs

> Built with Python, Flask.

Public latency graphs over time, RRD-based, with probes run from several nodes, plus a daily traceroute from every node to every target (traceping). The graphs and traces are public; the admin surface that manages targets is behind both the VPN ACL and SSO.

## Installation

```bash
git clone https://github.com/i-william-hr/smokeping.git
cd smokeping
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
```

## Usage

```bash
python3 smokeping.py
```

The smokeping.py entry point runs standalone.

## Tests

```bash
python3 -m unittest discover
```

## License

MIT License — see [LICENSE](LICENSE).
