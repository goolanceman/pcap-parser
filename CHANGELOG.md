# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] - 2026-07-15

### Added
- Initial release of `pcap-parser`.
- Extract AMR-NB, AMR-WB, and EVS RTP payloads from pcap/pcapng files.
- Support for RFC 4867 bandwidth-efficient framing and Iu framing.
- SIP/SDP parsing to auto-detect codec / payload-type mapping.
- Multi-flow extraction with per-flow filenames containing SSRC, codec, and direction.
- Single-flow legacy mode with `-o`.
- WAV conversion via `ffmpeg` with configurable sample rate (`-ar`).
- Optional per-flow RTP pcap export (`--pcaps`).
- Optional multichannel mix (`--mix`) aligned by pcap capture time.
- `--no-align-time` flag to start all mix channels at time 0.
- Silence / DTX preservation: inserts silence frames for RTP timestamp gaps and replaces SID frames with decodable silence.
- Audio-level analysis with `[SILENT]` flagging.
- Automatic per-extraction-folder `README.md` report with SIP summary, A/B party labels, and diagrams.
