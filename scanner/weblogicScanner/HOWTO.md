# WebLogic Scanner HOWTO

A fast and simplified WebLogic vulnerability scanner.

## Prerequisites

- Python 3.6+
- No additional dependencies required (standard library only).

## Basic Usage

To scan a single target:
```bash
python3 ws.py -t 127.0.0.1:7001
```

To scan multiple targets (addresses or file containing addresses):
```bash
python3 ws.py -t 127.0.0.1:7001 192.168.1.100:7001 targets.txt
```

## Options

| Option | Shorthand | Description |
| :--- | :--- | :--- |
| `--targets` | `-t` | **Required**. Target IP:Port or file containing targets (one per line). |
| `--vulnerability` | `-v` | Specific vulnerability modules to run (e.g., `console`, `cve_2020_14882`). |
| `--process_number` | `-p` | Number of concurrent processes (default: 8). |
| `--output` | `-o` | Directory path to save JSON results. |
| `--ssl` | `-s` | Force SSL (HTTPS/T3S). |

## Examples

### Scan for specific vulnerabilities
```bash
python3 ws.py -t 127.0.0.1:7001 -v console cve_2017_10271
```

### Save output to a directory
```bash
python3 ws.py -t targets.txt -o ./results -p 16
```

### Force SSL for all targets
```bash
python3 ws.py -t 192.168.1.1:7001 -s
```

## Module Directory
All vulnerability check modules are located in the `stars/` directory. You can use the filename (without `.py`) as the argument for `-v`.
