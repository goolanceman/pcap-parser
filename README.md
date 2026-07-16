# pcap-parser

Extract AMR, AMR-WB, and EVS audio from RTP pcaps and convert it to playable WAV files.

`pcap-parser` reads pcap/pcapng captures containing SIP signaling and RTP media, identifies audio flows by SSRC and payload type, and writes each flow in the RFC 4867 storage format. It can also decode to WAV with `ffmpeg`, export one pcap per flow, and mix all flows into a single multichannel WAV aligned by packet capture time — just like Wireshark's RTP player.

**Author:** Mansoor Khan  
**Version:** 1.1.0  
**License:** MIT

---

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage Examples](#usage-examples)
- [Command-Line Options](#command-line-options)
- [Output File Naming](#output-file-naming)
- [How It Works](#how-it-works)
- [WAV Output Notes](#wav-output-notes)
- [Troubleshooting](#troubleshooting)
- [Supported Codecs and Frame Sizes](#supported-codecs-and-frame-sizes)
- [Changelog](#changelog)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- Extracts **AMR-NB**, **AMR-WB**, and **EVS** RTP payloads.
- Supports **RFC 4867 bandwidth-efficient** framing and **Iu** framing.
- Handles pcaps with mixed **SIP + RTP** traffic.
- Parses **SDP** from SIP messages to auto-detect codec / payload-type mapping.
- **Single-flow mode** (`-o`): extracts the busiest matching RTP flow to one file.
- **Multi-flow mode** (default): extracts every matching RTP flow into a unique timestamped folder.
- Per-flow filenames include **SSRC, codec, source IP:port → destination IP:port**.
- Optional **WAV conversion** (`--wav`) using `ffmpeg`.
- Configurable **WAV sample rate** (`-ar` / `--sample-rate`, default 16 kHz).
- Clean WAV headers (no metadata chunks) and a soft peak limiter to avoid hard digital clipping.
- Per-flow **audio-level check**; silent or near-silent flows are flagged.
- **Preserves silent / DTX periods** by inserting silence frames for RTP timestamp gaps and replacing SID frames with decodable silence so `ffmpeg` does not drop them.
- Optional **per-flow RTP pcap export** (`--pcaps`) for Wireshark analysis.
- Optional **multichannel mix** (`--mix`) combining all flow WAVs into one file with one channel per flow, aligned by **pcap capture time** (Wireshark RTP-player style). Use `--no-align-time` to start all channels at 0.
- Optional **per-endpoint direction mixes** (`--direction-mix`): for every RTP socket (IP:port) the script creates incoming, outgoing and stereo WAVs (left = incoming, right = outgoing).
- Automatic **per-folder README report** in multi-flow mode with SIP call summary, A/B party direction labels, per-endpoint mixes, Mermaid + ASCII diagrams, and a listening guide.

---

## Requirements

- Python 3.7+
- Python packages:
  - `scapy`
  - `bitarray`
- `ffmpeg` (optional but strongly recommended for WAV output)

---

## Installation

1. Clone the repository:

```bash
git clone https://github.com/goolanceman/pcap-parser.git
cd pcap-parser
```

2. Install Python dependencies:

```bash
pip install scapy bitarray
```

3. Install `ffmpeg`:

```bash
# macOS
brew install ffmpeg

# Ubuntu / Debian
sudo apt-get install ffmpeg

# Windows (via chocolatey)
choco install ffmpeg
```

---

## Quick Start

```bash
python3 pcap_parser.py -i capture.pcap
```

This runs in **multi-flow mode**: every matching RTP flow is extracted into a folder named `capture_extracted_YYYYMMDD_HHMMSS`.

---

## Usage Examples

### Extract everything and convert to WAV

```bash
python3 pcap_parser.py -i capture.pcap --wav
```

### Extract only AMR-WB flows

```bash
python3 pcap_parser.py -i capture.pcap -c amr-wb --wav
```

### Extract a single busiest flow to a file

```bash
python3 pcap_parser.py -i capture.pcap -c amr-wb -o out.3ga --wav
```

### Extract with native AMR sample rate

```bash
python3 pcap_parser.py -i capture.pcap -c amr --wav -ar 8000
```

### Export one pcap per RTP flow

```bash
python3 pcap_parser.py -i capture.pcap --pcaps
```

### Mix all flows into one multichannel WAV

```bash
python3 pcap_parser.py -i capture.pcap -c amr --mix
```

The mixed file is aligned by **pcap capture time** by default. To start every channel at time 0:

```bash
python3 pcap_parser.py -i capture.pcap -c amr --mix --no-align-time
```

### Per-endpoint (IP:port) direction mixes

```bash
python3 pcap_parser.py -i capture.pcap --wav --direction-mix
```

This creates, for every RTP socket seen in the capture:

- `ipport_<ip>_<port>_incoming.wav` — all RTP streams **received** on that socket
- `ipport_<ip>_<port>_outgoing.wav` — all RTP streams **sent** from that socket
- `ipport_<ip>_<port>_stereo.wav` — stereo: left = incoming, right = outgoing

### Full analysis workflow

```bash
python3 pcap_parser.py -i capture.pcap -c amr --wav --pcaps --mix --direction-mix -ar 16000
```

This produces:
- Per-flow `.amr` raw codec files
- Per-flow `.amr.wav` audio files
- Per-flow `.pcap` files for Wireshark
- `mixed_all_flows.wav` with one channel per flow
- `ipport_<ip>_<port>_{incoming,outgoing,stereo}.wav` for every RTP socket
- `README.md` with SIP/RTP analysis and diagrams

---

## Command-Line Options

| Option | Description |
|--------|-------------|
| `-i <pcap>` | Input pcap/pcapng file (**required**) |
| `-c <codec>` | Codec: `amr`, `amr-wb`, `evs`, or `guess` (default: `guess`) |
| `-f <framing>` | Framing: `ietf` or `iu` (default: `ietf`) |
| `-o <file>` | Single output file (extracts busiest flow only) |
| `-d <dir>` | Output directory for multi-flow mode |
| `--wav` | Convert each output to WAV using `ffmpeg` |
| `-ar <rate>` / `--sample-rate <rate>` | WAV sample rate in Hz (default: `16000`) |
| `--pcaps` | Write one `.pcap` per RTP flow |
| `--mix` | Create one multichannel WAV mixing all flow WAVs |
| `--no-align-time` | With `--mix`, start all channels at time 0 instead of aligning by pcap capture time |
| `--direction-mix` | Create per-IP:port incoming/outgoing/stereo WAV mixes |
| `-h` | Show help |

---

## Output File Naming

In multi-flow mode, each file is named like:

```text
ssrc0x2174370c_amr_198.51.100.10:13414_to_192.0.2.20:22466.amr
ssrc0x2174370c_amr_198.51.100.10:13414_to_192.0.2.20:22466.amr.wav
ssrc0x2174370c_amr_198.51.100.10:13414_to_192.0.2.20:22466.pcap
```

The name contains:

- `ssrc0x...` — RTP SSRC identifier
- `amr` / `amr-wb` / `evs` — detected codec
- `<src_ip>:<src_port>_to_<dst_ip>:<dst_port>` — packet direction
- `.amr` / `.awb` / `.evs` — raw codec file
- `.wav` — WAV version (if `--wav` was used)
- `.pcap` — per-flow RTP pcap (if `--pcaps` was used)

When `--direction-mix` is used you also get:

- `ipport_<ip>_<port>_incoming.wav`
- `ipport_<ip>_<port>_outgoing.wav`
- `ipport_<ip>_<port>_stereo.wav`

---

## How It Works

1. Reads the pcap with `scapy`.
2. Parses every UDP payload:
   - SIP/SDP payloads are scanned to build a **payload-type → codec** map.
   - RTP payloads are parsed (version 2 only), handling CSRC lists, RTP extensions, and padding.
3. Groups RTP packets by `(SSRC, payload type)`.
4. Filters flows by codec (explicit or guessed) and ignores tiny / spurious flows.
5. Deduplicates packets by RTP sequence number and sorts them.
6. Preserves silent / DTX intervals by inserting silence frames for RTP timestamp gaps and replacing SID frames with silence (some `ffmpeg` builds drop SID / NO_DATA frames).
7. Writes each flow in RFC 4867 storage format.
8. If `--wav` is set, runs `ffmpeg` to convert to WAV at the requested sample rate.
9. If `--pcaps` is set, writes the original packets for each flow to a separate `.pcap` file.
10. If `--mix` is set, combines all flow WAVs into a single multichannel WAV aligned by pcap capture time, unless `--no-align-time` is used.
11. If `--direction-mix` is set, creates incoming / outgoing / stereo mixes for every RTP socket (IP:port).
12. Reports the RMS / peak level for each WAV and flags flows that are silent or extremely quiet.
13. Writes a per-folder `README.md` with SIP call summary, A/B direction labels, per-endpoint mixes, diagrams, and listening instructions.

---

## WAV Output Notes

WAV files are output at the sample rate chosen with `-ar` / `--sample-rate` (default **16 kHz**), as **16-bit, mono PCM**.

- **16 kHz** is the default because it is the native rate of AMR-WB and is widely supported.
- **AMR** is natively 8 kHz. Use `-ar 8000` for the original decoded sample rate.
- **AMR-WB** is natively 16 kHz.
- **EVS** can be decoded at various rates; 16 kHz is the default.

A soft peak limiter is applied during conversion to prevent the hard digital clipping that some AMR-NB decodes produce.

---

## Troubleshooting

### "No RTP packets found in pcap"

The pcap contains no UDP traffic that looks like RTP version 2. Verify with Wireshark or tshark that RTP is present.

### "Unable to guess the codec used"

Specify the codec explicitly:

```bash
python3 pcap_parser.py -i capture.pcap -c amr-wb
```

### WAV loads in Audacity but does not play

Make sure you are opening the `.wav` file, not the raw `.amr` / `.awb` / `.evs` file.

If a track is silent, check the extraction summary. Flows marked `[SILENT]` or below about `-60 dBFS` contain no usable audio in that direction. Try the opposite direction from the same call.

### Some flows are missing

Flows with fewer than 10 unique RTP packets are ignored as spurious. Edit `MIN_FRAMES` in `pcap_parser.py` if you need shorter flows.

### ffmpeg not found

Install `ffmpeg` and ensure it is in your `PATH`. WAV conversion is skipped if `ffmpeg` is missing.

---

## Supported Codecs and Frame Sizes

### AMR-NB (RFC 4867 bandwidth-efficient)

| Mode | Speech bits | Typical RTP payload bytes |
|------|-------------|---------------------------|
| 0    | 95          | 14                        |
| 1    | 103         | 15                        |
| 2    | 118         | 16                        |
| 3    | 134         | 18                        |
| 4    | 148         | 20                        |
| 5    | 159         | 22                        |
| 6    | 204         | 27                        |
| 7    | 244         | 32                        |
| SID  | 39          | 7                         |

### AMR-WB

| Mode | Speech bits | Typical RTP payload bytes |
|------|-------------|---------------------------|
| 0    | 132         | 18                        |
| 1    | 177         | 24                        |
| 2    | 253         | 33                        |
| 3    | 285         | 37                        |
| 4    | 317         | 41                        |
| 5    | 365         | 47                        |
| 6    | 397         | 51                        |
| 7    | 461         | 59                        |
| 8    | 477         | 61                        |
| SID  | 40          | 7                         |

### EVS

Compact payload format only (3GPP TS 26.445 Annex A.2). Supported payload sizes (bytes):

`6, 7, 17, 18, 20, 23, 24, 32, 33, 36, 40, 41, 46, 50, 58, 60, 61, 80, 120, 160, 240, 320`

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

---

## Contributing

Contributions, bug reports, and feature requests are welcome. Please open an issue or pull request on GitHub.

---

## License

MIT License — see [LICENSE](LICENSE) for details.
