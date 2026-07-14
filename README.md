# pcap_parser.py

Extract AMR, AMR-WB, and EVS audio from RTP pcaps and save it in the storage format defined in RFC 4867. The tool can also convert the extracted audio to WAV using `ffmpeg`, and it supports pcaps that contain both SIP signaling and RTP media.

**Author:** Mansoor Khan  
**Version:** 1.0.0

---

## Features

- Extracts **AMR**, **AMR-WB**, and **EVS** RTP payloads.
- Supports **bandwidth-efficient** RFC 4867 framing and **Iu** framing.
- Handles pcaps with **SIP + RTP** mixed traffic (SIP packets are ignored).
- Parses **SDP** from SIP messages to auto-detect codec / payload-type mapping.
- **Single-flow mode** (`-o`): extracts the busiest matching RTP flow to one file.
- **Multi-flow mode** (default): extracts every matching RTP flow into a unique timestamped folder.
- Per-flow filenames include **SSRC, codec, source IP:port → destination IP:port**.
- Optional **WAV conversion** (`--wav`) using `ffmpeg`.
- Configurable **WAV sample rate** (`-ar` / `--sample-rate`, default 16 kHz).
- WAV output uses clean headers (no metadata chunks) and a soft peak limiter to avoid hard digital clipping.
- Per-flow **audio-level check** in the summary; silent or near-silent flows are flagged.
- Multi-flow mode extracts **all supported codec flows** by default when no `-c` is given.
- Optional **per-flow RTP pcap export** (`--pcaps`) so each SSRC gets its own `.pcap` for Wireshark analysis or later decoding.
- Optional **multichannel mix** (`--mix`) that combines all flow WAVs into one WAV with one channel per flow, so you can open a single file in Audacity and split it into per-SSRC tracks.
- Deduplicates RTP packets by sequence number and sorts them before writing.
- **Preserves silent/DTX periods** by inserting silence frames for RTP timestamp gaps and replacing SID frames with silence so ffmpeg does not drop them.
- Prints a clear extraction summary with flow details.
- **Automatic per-folder README report** in multi-flow mode: includes SIP call summary, A/B party direction labels, Mermaid + ASCII diagrams, and a plain-English listening guide.

---

## Requirements

- Python 3
- Python packages:
  - `scapy`
  - `bitarray`
- (Optional but recommended) `ffmpeg` for WAV output.

Install dependencies:

```bash
pip install scapy bitarray
```

Install `ffmpeg` (macOS example):

```bash
brew install ffmpeg
```

---

## Basic Usage

```bash
python3 pcap_parser.py -i capture.pcap
```

This runs in **multi-flow mode**: every matching RTP flow is extracted into a folder named `capture_extracted_YYYYMMDD_HHMMSS`.

### Convert everything to WAV

```bash
python3 pcap_parser.py -i capture.pcap --wav
```

### Specify a codec

```bash
python3 pcap_parser.py -i capture.pcap -c amr-wb --wav
python3 pcap_parser.py -i capture.pcap -c amr --wav
python3 pcap_parser.py -i capture.pcap -c evs --wav
```

If you don't specify `-c`, the script extracts every flow whose codec it can identify (AMR, AMR-WB, or EVS).

### Single output file (legacy / single-flow mode)

```bash
python3 pcap_parser.py -i capture.pcap -o out.3ga --wav
```

This extracts only the busiest matching flow.

### Custom output directory

```bash
python3 pcap_parser.py -i capture.pcap -d my_output --wav
```

### Change the WAV sample rate

```bash
# default 16 kHz (best general compatibility)
python3 pcap_parser.py -i capture.pcap -c amr --wav

# native AMR sample rate
python3 pcap_parser.py -i capture.pcap -c amr --wav -ar 8000

# higher rate for AMR-WB / EVS
python3 pcap_parser.py -i capture.pcap -c amr-wb --wav -ar 16000
```

### Extract one pcap per RTP flow

```bash
# write a separate .pcap for each SSRC (useful for Wireshark)
python3 pcap_parser.py -i capture.pcap --pcaps

# audio + per-flow pcaps together
python3 pcap_parser.py -i capture.pcap -c amr --wav --pcaps
```

### Mix all flows into one multichannel WAV

```bash
# one WAV with one channel per SSRC (no need for --wav; it is enabled automatically)
python3 pcap_parser.py -i capture.pcap -c amr --mix

# combine with pcaps and custom sample rate
python3 pcap_parser.py -i capture.pcap --wav --pcaps --mix -ar 16000
```

In Audacity, import `mixed_all_flows.wav`. If Audacity asks how to import a multichannel file, choose **“Split to mono tracks”** (or use **Tracks → Mix → Stereo Track to Mono** / **Split Stereo to Mono**) so each SSRC appears as its own track.

---

## Output File Naming

In multi-flow mode, each file is named like:

```text
ssrc0x2174370c_amr_81.11.118.155:13414_to_10.135.84.10:22466.amr
ssrc0x2174370c_amr_81.11.118.155:13414_to_10.135.84.10:22466.amr.wav
ssrc0x2174370c_amr_81.11.118.155:13414_to_10.135.84.10:22466.pcap
```

The name contains:

- `ssrc0x...` — RTP SSRC identifier
- `amr` / `amr-wb` / `evs` — detected codec
- `<src_ip>:<src_port>_to_<dst_ip>:<dst_port>` — packet direction
- `.amr` / `.awb` / `.evs` — raw codec file
- `.wav` — WAV version (if `--wav` was used)
- `.pcap` — per-flow RTP pcap (if `--pcaps` was used)

---

## Per-Folder README Report

Every multi-flow extraction now writes a `README.md` inside the output folder. It contains:

- **Run details** — input pcap, command used, packet counts.
- **SIP Call Summary** — Caller (A-party), Callee (B-party), and media endpoints parsed from SDP.
- **Extracted RTP Flows** — SSRC, codec, direction (`A -> B` / `B -> A`), source/destination, duration, audio level, output filename, and a Wireshark filter.
- **Call Direction Guide** — maps each Call-ID to the captured A→B and B→A flows.
- **SIP + RTP Diagrams** — Mermaid sequence diagram and ASCII overview so you can see at a glance who is talking to whom.
- **Listening instructions** — how to play the individual files and how to split the multichannel `mixed_all_flows.wav` in Audacity.

This is designed so a non-expert can open the folder, read the report, and understand which audio file belongs to which party.

---

## Examples

### Example 1: Extract a single AMR-WB flow

```bash
python3 pcap_parser.py -i 0xe94ed2e6.pcap -c amr-wb -o out.3ga --wav
# or with a specific sample rate:
python3 pcap_parser.py -i 0xe94ed2e6.pcap -c amr-wb -o out.3ga --wav -ar 16000
```

Expected output:

```text
Number of packets read from pcap: 56589
Number of RTP packets found: 50428
SDP hints: {104: 'amr-wb', 110: 'amr-wb', 102: 'amr', 108: 'amr', 109: 'evs'}
Selected RTP flow: SSRC=0xe94ed2e6, PT=104
Extracted: codec=amr-wb, frames=2964, bad=0
Converted to WAV: out.wav
WAV output ready: out.wav
  duration=55.62s  peak=25811  RMS=-26.5 dBFS
```

### Example 2: Extract all AMR flows from a SIP+RTP pcap

```bash
python3 pcap_parser.py -i norbtvodafone00.pcap -c amr --wav
```

Expected output:

```text
Output directory: norbtvodafone00_extracted_20260714_235612
...
=== Extraction Summary ===
              SSRC     PT    Codec                   Source -> Destination                Frames        Level   Extras Output
------------------------------------------------------------------------------------------------------------------------------------------------------
        0x065779f7    102      amr       172.15.2.222:52956 -> 10.135.84.20:27830             87   -24.2 dBFS      - norbtvodafone00_extracted_20260714_235612/ssrc0x065779f7_amr_172.15.2.222:52956_to_10.135.84.20:27830.amr.wav
        0x1be8e2f8    102      amr        81.11.118.87:2720 -> 10.135.84.10:22464           1270   -25.4 dBFS      - norbtvodafone00_extracted_20260714_235612/ssrc0x1be8e2f8_amr_81.11.118.87:2720_to_10.135.84.10:22464.amr.wav
        0x2174370c    102      amr      81.11.118.155:13414 -> 10.135.84.10:22466           1563   -18.2 dBFS      - norbtvodafone00_extracted_20260714_235612/ssrc0x2174370c_amr_81.11.118.155:13414_to_10.135.84.10:22466.amr.wav
        0x7d267b62    102      amr       81.11.118.96:39400 -> 10.135.84.10:22460            487   -22.7 dBFS      - norbtvodafone00_extracted_20260714_235612/ssrc0x7d267b62_amr_81.11.118.96:39400_to_10.135.84.10:22460.amr.wav
        0x804531be    102      amr       172.15.2.222:41280 -> 10.135.84.20:27828             87   -24.2 dBFS      - norbtvodafone00_extracted_20260714_235612/ssrc0x804531be_amr_172.15.2.222:41280_to_10.135.84.20:27828.amr.wav
        0xc1f0d513    102      amr      81.11.118.201:12600 -> 10.135.84.10:22462            585 -88.9 dBFS [SILENT]      - norbtvodafone00_extracted_20260714_235612/ssrc0xc1f0d513_amr_81.11.118.201:12600_to_10.135.84.10:22462.amr.wav

Total flows extracted: 6
All WAV files are 16000 Hz, 16-bit mono PCM.
```

### Example 3: Iu framing

```bash
python3 pcap_parser.py -i capture.pcap -c amr-wb -f iu -o out_iu.3ga --wav
```

### Example 4: Extract audio + one pcap per RTP flow

```bash
python3 pcap_parser.py -i norbtvodafone00.pcap -c amr --wav --pcaps
```

This creates both `.amr`/`.amr.wav` files and a separate `.pcap` for each SSRC, named like:

```text
ssrc0x2174370c_amr_81.11.118.155:13414_to_10.135.84.10:22466.pcap
```

You can open that pcap in Wireshark and use a display filter such as `rtp.ssrc == 0x2174370c`.

### Example 5: Mix all flows into a single multichannel WAV

```bash
python3 pcap_parser.py -i norbtvodafone00.pcap -c amr --mix
```

This creates the usual per-flow files plus:

```text
norbtvodafone00_extracted_YYYYMMDD_HHMMSS/mixed_all_flows.wav
```

Output:

```text
Mixed multichannel WAV: norbtvodafone00_extracted_20260715_000750/mixed_all_flows.wav
Mixed all 6 flow(s) into: norbtvodafone00_extracted_20260715_000750/mixed_all_flows.wav
  duration=29.98s  channels=6
```

Open `mixed_all_flows.wav` in Audacity and split the channels into mono tracks to see/hear each SSRC separately.

---

## Command-Line Options

| Option | Description |
|--------|-------------|
| `-i <pcap>` | Input pcap/pcapng file (**required**) |
| `-c <codec>` | Codec: `amr`, `amr-wb`, `evs`, or `guess` (default: `guess`) |
| `-f <framing>` | Framing: `ietf` or `iu` (default: `ietf`) |
| `-o <file>` | Single output file (extracts busiest flow only) |
| `-d <dir>` | Output directory for multi-flow mode |
| `--wav` | Also convert each output to WAV using `ffmpeg` |
| `-ar <rate>` / `--sample-rate <rate>` | WAV sample rate in Hz (default: `16000`) |
| `--pcaps` | Also write one `.pcap` per RTP flow (SSRC + PT) |
| `--mix` | Also create one multichannel WAV mixing all flow WAVs |
| `-h` | Show help |

---

## How It Works

1. Reads the pcap with `scapy`.
2. Parses every UDP payload:
   - SIP/SDP payloads are scanned to build a **payload-type → codec** map.
   - RTP payloads are parsed (version 2 only), handling CSRC lists, RTP extensions, and padding.
3. Groups RTP packets by `(SSRC, payload type)`.
4. Filters flows by codec (explicit or guessed) and ignores tiny / spurious flows.
5. Deduplicates packets by RTP sequence number and sorts them.
6. Preserves silent/DTX intervals by inserting silence frames for RTP timestamp gaps and replacing SID frames with silence (some ffmpeg builds drop SID/NO_DATA frames).
7. Writes each flow in RFC 4867 storage format:
   - `#!AMR\n` for AMR
   - `#!AMR-WB\n` for AMR-WB
   - `#!EVS_MC1.0\n` plus header for EVS
8. If `--wav` is set, runs `ffmpeg` to convert to WAV at the requested sample rate (`-ar`), using a clean WAV header and a soft peak limiter to avoid hard clipping.
9. If `--pcaps` is set, writes the original packets for each flow to a separate `.pcap` file.
10. If `--mix` is set, combines all flow WAVs into a single multichannel WAV (`mixed_all_flows.wav`) with one channel per flow.
11. Reports the RMS/peak level for each WAV in the summary and flags flows that are silent or extremely quiet.

---

## WAV Output Notes

WAV files are output at the sample rate chosen with `-ar` / `--sample-rate` (default **16 kHz**), as **16-bit, mono PCM**.

- The default is **16 kHz** because it is the native rate of AMR-WB and is widely supported by players and editors.
- AMR is natively 8 kHz. Use `-ar 8000` if you want the original decoded sample rate.
- AMR-WB is natively 16 kHz.
- EVS can be decoded at various rates; 16 kHz is the default.

The WAV files are written with a minimal RIFF/WAVE header (no `LIST`/`INFO` metadata chunks) and a soft peak limiter is applied during conversion. This prevents the hard digital clipping that some AMR-NB decodes produce at full scale and improves compatibility with Audacity and other editors.

If you need the original sample rate for AMR, run:

```bash
python3 pcap_parser.py -i capture.pcap -c amr --wav -ar 8000
```

The `--mix` output is a multichannel WAV (one channel per SSRC). Audacity can import it and split the channels into separate mono tracks so each flow is visible individually.

---

## Troubleshooting

### "No RTP packets found in pcap"

The pcap contains no UDP traffic that looks like RTP version 2. Check with Wireshark/tshark that RTP is present.

### "Unable to guess the codec used"

The script could not match payload sizes to known AMR/AMR-WB/EVS sizes. Specify the codec explicitly:

```bash
python3 pcap_parser.py -i capture.pcap -c amr-wb
```

### WAV loads in Audacity but does not play

Make sure you are opening the `.wav` file, not the raw `.amr` / `.awb` / `.evs` file.

The WAVs produced by this script are clean 16 kHz PCM with a soft peak limiter applied, which prevents the hard clipping that made some AMR-NB WAVs unplayable in Audacity in earlier versions. They should play in Audacity, VLC, Preview, and most modern players.

If you still hear nothing:

- Check the **track gain** and **master gain** in Audacity.
- Check the extraction summary: flows marked `[SILENT]` or with a level below about `-60 dBFS` contain no usable audio in the captured direction.
- Try VLC or ffplay:

```bash
ffplay output.wav
```

### Some flows are silent

A flow marked `[SILENT]` in the summary means the captured RTP direction contains only comfort-noise / SID frames, DTX gaps, or packets with very low signal. This is normal for the receive direction of a muted or one-way audio call. Play the other direction(s) from the same call to hear the conversation.

### Some flows are missing

Flows with fewer than **10 unique RTP packets** are ignored as spurious. If you need very short flows, the threshold can be changed in `pcap_parser.py` by editing `MIN_FRAMES`.

### ffmpeg not found

Install `ffmpeg` and ensure it is in your `PATH`. WAV conversion is skipped if `ffmpeg` is missing.

---

## Supported Codecs and Frame Sizes

### AMR (RFC 4867 bandwidth-efficient)

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

## Development

To run with debug logging, inspect `pcap_parser.log` after execution.

---

## License

Use at your own risk. This tool was built for debugging and analysis of captured RTP streams.
