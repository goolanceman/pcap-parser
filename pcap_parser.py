"""
pcap-parser: Extract AMR, AMR-WB and EVS audio from RTP pcaps.

Reads pcap/pcapng files containing SIP/RTP traffic, extracts RTP flows for
AMR (NB), AMR-WB and EVS codecs, and writes them in RFC 4867 storage format.
Optionally converts to WAV, exports one pcap per flow, and mixes all flows
into a single multichannel WAV aligned by pcap capture time.

Supported RTP framing:
  - RFC 4867 bandwidth-efficient mode (default)
  - Iu framing (3GPP TS 25.415) for AMR / AMR-WB

Author: Mansoor Khan
Version: 1.1.0
License: MIT
"""

__version__ = '1.1.0'
__author__ = 'Mansoor Khan'
__license__ = 'MIT'

import sys
import os
import argparse
import logging
import struct
import re
import subprocess
import shutil
import math
import wave
from datetime import datetime
from collections import Counter
from scapy.all import rdpcap, wrpcap, UDP
from bitarray import bitarray

supported_codecs = ['guess', 'amr', 'amr-wb', 'evs']

# Optional forced RTP payload type. Set to None to auto-select.
FORCED_PAYLOAD_TYPE = None

# Bandwidth-efficient RTP payload sizes (including header) for each codec mode.
# These are used to identify the codec/flow and to sanity-check the FT value.
amr_payload_sizes = [14, 15, 16, 18, 20, 22, 27, 32, 7]
amrwb_payload_sizes = [18, 24, 33, 37, 41, 47, 51, 59, 61, 7]
evs_payload_sizes = [6, 7, 17, 18, 20, 23, 24, 32, 33, 36, 40, 41, 46, 50, 58, 60, 61, 80, 120, 160, 240, 320]

# Iu payload type 0/1 sizes (including Iu framing header)
amr_payload_sizes_iupt0 = [16, 17, 19, 21, 23, 24, 30, 35, 9]
amrwb_payload_sizes_iupt0 = [21, 27, 36, 40, 44, 50, 54, 62, 64, 9]
amr_payload_sizes_iupt1 = [15, 16, 18, 20, 22, 23, 29, 34, 8]
amrwb_payload_sizes_iupt1 = [20, 26, 35, 39, 43, 49, 53, 61, 63, 8]

# IuUP framing protocol params
fn = -1  # Frame number in Iu framing
num_control_frames = 0
num_bad_frames = 0


def get_expected_payload_sizes(codec, framing):
    '''Return the set of expected payload sizes for the given codec and framing.'''
    if framing == 'ietf':
        if codec == 'amr':
            return set(amr_payload_sizes)
        elif codec == 'amr-wb':
            return set(amrwb_payload_sizes)
        elif codec == 'evs':
            return set(evs_payload_sizes)
    else:  # iu
        if codec == 'amr':
            return set(amr_payload_sizes_iupt0 + amr_payload_sizes_iupt1)
        elif codec == 'amr-wb':
            return set(amrwb_payload_sizes_iupt0 + amrwb_payload_sizes_iupt1)
    return set()


def parse_sdp(payload):
    '''
    Parse a SIP/SDP payload and return a dict mapping payload type to codec name.
    Only looks for audio m-lines and a=rtpmap attributes.
    '''
    sdp_map = {}
    try:
        text = payload.decode('utf-8', errors='ignore')
    except Exception:
        return sdp_map

    # Find audio media line: m=audio <port> RTP/AVP <pt list>
    for mline in re.finditer(r'^m=audio\s+\d+\s+\w+/\w+\s+(.+)$', text, re.MULTILINE):
        pts = mline.group(1).split()
        for pt_str in pts:
            try:
                pt = int(pt_str)
            except ValueError:
                continue
            # Look for a=rtpmap:<pt> <codec>/<rate>
            pattern = r'^a=rtpmap:\s*{}\s+([^/\s]+)/(\d+)'.format(re.escape(pt_str))
            match = re.search(pattern, text, re.MULTILINE)
            if match:
                codec_name = match.group(1).lower()
                rate = int(match.group(2))
                if codec_name in ('amr', 'amr-wb'):
                    sdp_map[pt] = codec_name
                elif codec_name == 'evs':
                    sdp_map[pt] = 'evs'
                elif 'amr' in codec_name and rate == 16000:
                    sdp_map[pt] = 'amr-wb'
                elif 'amr' in codec_name and rate == 8000:
                    sdp_map[pt] = 'amr'
    return sdp_map


def extract_sdp_hints(packets):
    '''
    Scan all UDP packets for SIP/SDP and return a dict mapping PT to codec name.
    '''
    hints = {}
    sip_starts = (b'SIP/2.0', b'INVITE ', b'OPTIONS ', b'REGISTER ',
                  b'ACK ', b'BYE ', b'CANCEL ', b'UPDATE ', b'PRACK ',
                  b'SUBSCRIBE ', b'NOTIFY ', b'PUBLISH ', b'REFER ',
                  b'MESSAGE ')
    for packet in packets:
        if UDP not in packet:
            continue
        data = bytes(packet[UDP].payload)
        if not data.startswith(sip_starts):
            continue
        sdp_map = parse_sdp(data)
        hints.update(sdp_map)
    return hints


def _extract_tag(header):
    '''Extract the ;tag= value from a From/To/Contact header.'''
    if not header:
        return None
    m = re.search(r';tag=([^;\s]+)', header, re.IGNORECASE)
    return m.group(1) if m else None


def _extract_uri(header):
    '''Extract the SIP URI (or display name) from a From/To/Contact header.'''
    if not header:
        return None
    # Look for <sip:...> first, otherwise take the first token.
    m = re.search(r'<([^>]+)>', header)
    if m:
        return m.group(1)
    parts = header.split(';')
    return parts[0].strip() if parts else None


def parse_sdp_full(payload):
    '''
    Parse a SIP/SDP body and return a dict with connection IP, media port,
    payload types and rtpmap info.
    '''
    sdp = {'connection': None, 'media_port': None, 'pts': [], 'rtpmap': {}}
    try:
        text = payload.decode('utf-8', errors='ignore')
    except Exception:
        return sdp

    # Connection address: c=IN IP4 <ip>
    cm = re.search(r'^c=\S+\s+\S+\s+(\S+)', text, re.MULTILINE)
    if cm:
        sdp['connection'] = cm.group(1)

    # Audio media line
    mm = re.search(r'^m=audio\s+(\d+)\s+\S+\s+(.*)$', text, re.MULTILINE)
    if mm:
        sdp['media_port'] = int(mm.group(1))
        for pt_str in mm.group(2).split():
            try:
                sdp['pts'].append(int(pt_str))
            except ValueError:
                continue

    # a=rtpmap lines
    for rm in re.finditer(r'^a=rtpmap:\s*(\d+)\s+([^/\s]+)/(\d+)', text, re.MULTILINE):
        pt = int(rm.group(1))
        sdp['rtpmap'][pt] = {'codec': rm.group(2).lower(), 'rate': int(rm.group(3))}

    return sdp


def parse_sip_message(data, src_ip, src_port, dst_ip, dst_port):
    '''
    Parse a SIP message from UDP payload bytes.
    Returns a dict with method, Call-ID, From/To, tags, CSeq, Contact and SDP.
    Returns None if the payload is not a SIP message.
    '''
    try:
        text = data.decode('utf-8', errors='ignore')
    except Exception:
        return None

    lines = text.splitlines()
    if not lines:
        return None

    first = lines[0].strip()
    if first.startswith('SIP/2.0'):
        is_request = False
        method = None
        status_code = None
        parts = first.split()
        if len(parts) >= 2:
            try:
                status_code = int(parts[1])
            except ValueError:
                pass
    else:
        is_request = True
        status_code = None
        parts = first.split()
        method = parts[0] if parts else None

    headers = {}
    last_header = None
    i = 1
    while i < len(lines):
        line = lines[i]
        if not line:
            break
        if line.startswith((' ', '\t')) and last_header is not None:
            headers[last_header] += ' ' + line.strip()
            i += 1
            continue
        m = re.match(r'^([^:\r\n]+):\s*(.*)$', line)
        if m:
            hname = m.group(1).strip().lower()
            hval = m.group(2).strip()
            headers[hname] = hval
            last_header = hname
        i += 1

    body_start = i + 1
    body = '\n'.join(lines[body_start:]) if body_start < len(lines) else ''

    cseq = headers.get('cseq', '')
    cseq_method = None
    if cseq:
        cseq_parts = cseq.split()
        if len(cseq_parts) >= 2:
            cseq_method = cseq_parts[1]

    if not method:
        method = cseq_method

    content_type = headers.get('content-type', '').lower()
    sdp = None
    if 'sdp' in content_type:
        sdp = parse_sdp_full(body.encode('utf-8', errors='ignore'))

    return {
        'is_request': is_request,
        'method': method,
        'status_code': status_code,
        'call_id': headers.get('call-id'),
        'from_header': headers.get('from'),
        'to_header': headers.get('to'),
        'from_uri': _extract_uri(headers.get('from', '')),
        'to_uri': _extract_uri(headers.get('to', '')),
        'from_tag': _extract_tag(headers.get('from', '')),
        'to_tag': _extract_tag(headers.get('to', '')),
        'cseq': cseq,
        'contact': headers.get('contact'),
        'src_ip': src_ip,
        'src_port': src_port,
        'dst_ip': dst_ip,
        'dst_port': dst_port,
        'sdp': sdp,
    }


def extract_sip_messages(packets):
    '''
    Scan all UDP packets and return a list of parsed SIP messages.
    '''
    from scapy.layers.inet import IP
    sip_starts = (b'SIP/2.0', b'INVITE ', b'OPTIONS ', b'REGISTER ',
                  b'ACK ', b'BYE ', b'CANCEL ', b'UPDATE ', b'PRACK ',
                  b'SUBSCRIBE ', b'NOTIFY ', b'PUBLISH ', b'REFER ',
                  b'MESSAGE ')
    messages = []
    for packet in packets:
        if UDP not in packet or IP not in packet:
            continue
        data = bytes(packet[UDP].payload)
        if not data.startswith(sip_starts):
            continue
        msg = parse_sip_message(data, packet[IP].src, packet[UDP].sport,
                                packet[IP].dst, packet[UDP].dport)
        if msg:
            messages.append(msg)
    return messages


def build_sip_dialogs(sip_messages):
    '''
    Group SIP messages by Call-ID and identify caller/callee and media
    endpoints from the first INVITE/200 OK exchange.
    Returns a dict call_id -> dialog info.
    '''
    dialogs = {}
    for msg in sip_messages:
        cid = msg.get('call_id')
        if not cid:
            continue
        if cid not in dialogs:
            dialogs[cid] = {
                'messages': [],
                'caller': None,
                'callee': None,
                'caller_media': None,
                'callee_media': None,
                'call_id': cid,
            }
        dialogs[cid]['messages'].append(msg)

    for cid, dialog in dialogs.items():
        # Find the original INVITE request (lowest CSeq) to set caller/callee.
        invite_requests = [m for m in dialog['messages']
                           if m.get('is_request') and m.get('method') == 'INVITE']
        original_invite = None
        for msg in invite_requests:
            try:
                cseq_num = int(msg.get('cseq', '0').split()[0])
            except Exception:
                cseq_num = 0
            msg['_cseq_num'] = cseq_num
        if invite_requests:
            original_invite = min(invite_requests, key=lambda m: m.get('_cseq_num', 0))

        if original_invite:
            dialog['caller'] = {
                'ip': original_invite['src_ip'],
                'port': original_invite['src_port'],
                'uri': original_invite.get('from_uri'),
            }
            dialog['callee'] = {
                'ip': original_invite['dst_ip'],
                'port': original_invite['dst_port'],
                'uri': original_invite.get('to_uri'),
            }
            if original_invite.get('sdp'):
                dialog['caller_media'] = original_invite['sdp']

        if not dialog.get('caller'):
            continue

        def _valid_sdp(sdp):
            return sdp and sdp.get('media_port') and sdp.get('connection')

        # Capture any SDP sent by the caller (offer in INVITE/UPDATE/PRACK).
        for msg in dialog['messages']:
            if (msg.get('is_request') and msg.get('method') in ('INVITE', 'UPDATE', 'PRACK') and
                    msg.get('src_ip') == dialog['caller']['ip'] and
                    _valid_sdp(msg.get('sdp')) and not dialog.get('caller_media')):
                dialog['caller_media'] = msg['sdp']

        # Find the first reliable 1xx/2xx answer with SDP to get callee media.
        for msg in dialog['messages']:
            if (not msg.get('is_request') and msg.get('status_code') and
                    180 <= msg.get('status_code') < 300 and
                    msg.get('method') == 'INVITE' and _valid_sdp(msg.get('sdp'))):
                dialog['callee_media'] = msg['sdp']
                break

    # Keep only dialogs that contain an INVITE request (real calls).
    return {cid: d for cid, d in dialogs.items() if d.get('caller') is not None}


def _media_endpoint(media, fallback_ip):
    '''Return (ip, port) tuple for a media dict, falling back to signaling IP.'''
    ip = media.get('connection') or fallback_ip
    port = media.get('media_port')
    return ip, port


def _matches_endpoint(ip, port, media_ip, media_port):
    '''True if IP matches and, when media_port is known, port matches too.'''
    if ip != media_ip:
        return False
    if media_port is None:
        return True
    return port == media_port


def label_flows_with_sip(flows, packets, sip_dialogs):
    '''
    Try to label each RTP flow as A->B, B->A, A-party or B-party using
    SIP dialog media endpoints. Returns a dict flow -> label info.
    '''
    labels = {}
    for flow in flows:
        ssrc, pt = flow
        endpoints = get_flow_endpoints(packets, ssrc, pt)
        if not endpoints:
            labels[flow] = {'direction': 'Unknown', 'call_id': None, 'note': 'No endpoints'}
            continue
        src_ip, src_port, dst_ip, dst_port = endpoints

        best_match = None
        best_score = 0  # 3 = exact, 2 = ip-only, 1 = dst-only
        for cid, dialog in sip_dialogs.items():
            a_media = dialog.get('caller_media')
            b_media = dialog.get('callee_media')
            caller = dialog.get('caller')
            callee = dialog.get('callee')
            if not caller or not callee:
                continue

            a_ip, a_port = _media_endpoint(a_media, caller['ip']) if a_media else (caller['ip'], None)
            b_ip, b_port = _media_endpoint(b_media, callee['ip']) if b_media else (callee['ip'], None)

            # Exact endpoint match (both src and dst with port when known)
            if (_matches_endpoint(src_ip, src_port, a_ip, a_port) and
                    _matches_endpoint(dst_ip, dst_port, b_ip, b_port)):
                best_match = (cid, 'A -> B')
                best_score = 3
                break
            if (_matches_endpoint(src_ip, src_port, b_ip, b_port) and
                    _matches_endpoint(dst_ip, dst_port, a_ip, a_port)):
                best_match = (cid, 'B -> A')
                best_score = 3
                break

            # IP-only match (handles NAT / missing port info)
            if best_score < 2:
                if src_ip == a_ip and dst_ip == b_ip:
                    best_match = (cid, 'A -> B')
                    best_score = 2
                elif src_ip == b_ip and dst_ip == a_ip:
                    best_match = (cid, 'B -> A')
                    best_score = 2

            # One-sided match: destination tells us who is receiving
            if best_score < 1:
                if _matches_endpoint(dst_ip, dst_port, b_ip, b_port):
                    best_match = (cid, 'A -> B')
                    best_score = 1
                elif _matches_endpoint(dst_ip, dst_port, a_ip, a_port):
                    best_match = (cid, 'B -> A')
                    best_score = 1

            # One-sided match: source tells us who is sending
            if best_score < 1:
                if _matches_endpoint(src_ip, src_port, a_ip, a_port):
                    best_match = (cid, 'A -> B')
                    best_score = 1
                elif _matches_endpoint(src_ip, src_port, b_ip, b_port):
                    best_match = (cid, 'B -> A')
                    best_score = 1

        if best_match:
            cid, direction = best_match
            labels[flow] = {
                'direction': direction,
                'call_id': cid,
                'a_party': sip_dialogs[cid]['caller'],
                'b_party': sip_dialogs[cid]['callee'],
            }
        else:
            labels[flow] = {
                'direction': 'Unknown',
                'call_id': None,
                'note': 'No matching SIP dialog',
            }
    return labels


def find_evs_decoder():
    '''
    Locate the 3GPP EVS reference decoder binary (EVS_dec).
    Returns the path or None if not found.
    '''
    env_path = os.environ.get('EVS_DEC')
    if env_path and os.path.isfile(env_path) and os.access(env_path, os.X_OK):
        return env_path
    return shutil.which('EVS_dec')


def write_evs_voip_file(rtp_packets, ssrc, pt, voip_file):
    '''
    Write a G.192 VOIP file for the 3GPP EVS decoder from an RTP flow.
    The VOIP file contains the RTP payload bits in G.192 format so that
    EVS_dec -VOIP can parse the RTP/EVS framing correctly.
    Returns True on success.
    '''
    G192_SYNC_GOOD_FRAME = 0x6B21
    G192_BIT0 = 0x007F
    G192_BIT1 = 0x0081
    RTP_HEADER_PART1 = 22

    selected = [p for p in rtp_packets
                if p['sourcesync'] == ssrc and p['payload_type'] == pt]
    if not selected:
        return False

    # Sort by sequence number; keep first duplicate.
    selected.sort(key=lambda x: x['sequence'])
    seen_seq = set()
    unique = []
    for p in selected:
        if p['sequence'] not in seen_seq:
            seen_seq.add(p['sequence'])
            unique.append(p)

    try:
        with open(voip_file, 'wb') as f:
            # Arbitrary start time; EVS_dec VOIP mode only needs monotonic times.
            rcv_time_ms = 0
            for p in unique:
                payload = p['payload']
                rtp_packet_size = 12 + len(payload)
                # Host byte order (decoder reads these as native uint32/uint16)
                f.write(struct.pack('<I', rtp_packet_size))
                f.write(struct.pack('<I', rcv_time_ms))
                f.write(struct.pack('<H', RTP_HEADER_PART1))
                f.write(struct.pack('>H', p['sequence']))
                f.write(struct.pack('>I', p['timestamp']))
                f.write(struct.pack('<I', ssrc))
                num_bits = len(payload) * 8
                f.write(struct.pack('<H', G192_SYNC_GOOD_FRAME))
                f.write(struct.pack('<H', num_bits))
                for byte in payload:
                    for i in range(7, -1, -1):
                        bit = (byte >> i) & 1
                        f.write(struct.pack('<H', G192_BIT1 if bit else G192_BIT0))
                rcv_time_ms += 20
        return True
    except Exception as e:
        logging.error('Failed to write VOIP file {}: {}'.format(voip_file, e))
        return False


def convert_evs_to_wav(rtp_packets, ssrc, pt, wav_file, sample_rate):
    '''
    Convert an EVS RTP flow to WAV using the 3GPP EVS reference decoder
    in VOIP mode. The decoder receives a G.192 VOIP file and outputs raw
    16-bit PCM, which is then wrapped in a WAV container.
    Returns True on success, False on failure.
    '''
    evs_dec = find_evs_decoder()
    if not evs_dec:
        print('EVS_dec not found; cannot convert EVS to WAV. Set EVS_DEC env var.')
        return False

    # Output sample rate for EVS_dec: 8, 16, 32 or 48 kHz.
    fs_map = {8000: 8, 16000: 16, 32000: 32, 48000: 48}
    if sample_rate not in fs_map:
        print('Unsupported EVS output sample rate: {} Hz'.format(sample_rate))
        return False
    fs_khz = fs_map[sample_rate]

    tmpdir = os.path.dirname(wav_file) or '.'
    voip_file = os.path.join(tmpdir, 'tmp_evs_voip_{:08x}_{}.g192'.format(ssrc, pt))
    raw_file = voip_file + '.16k'

    if not write_evs_voip_file(rtp_packets, ssrc, pt, voip_file):
        return False

    cmd = [evs_dec, '-VOIP', '-q', str(fs_khz), voip_file, raw_file]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            print('EVS_dec conversion failed:')
            print(result.stderr[-1000:])
            return False
    except Exception as e:
        print('Error running EVS_dec: {}'.format(e))
        return False
    finally:
        try:
            os.remove(voip_file)
        except OSError:
            pass

    if not os.path.isfile(raw_file):
        print('EVS_dec did not produce output file')
        return False

    # Wrap raw 16-bit host-endian PCM in WAV.
    try:
        with open(raw_file, 'rb') as f:
            pcm = f.read()
        with wave.open(wav_file, 'wb') as w:
            w.setnchannels(1)
            w.setsampwidth(2)
            w.setframerate(sample_rate)
            w.writeframes(pcm)
        print('Converted to WAV: {}'.format(wav_file))
        return True
    except Exception as e:
        print('Error writing WAV from EVS_dec output: {}'.format(e))
        return False
    finally:
        try:
            os.remove(raw_file)
        except OSError:
            pass


def convert_to_wav(amr_file, wav_file, sample_rate):
    '''
    Convert the produced AMR/AMR-WB file to WAV using ffmpeg.
    The output is mono PCM. A small headroom limiter is applied so that
    hard-clipped peaks (common with AMR-NB decodes) do not sit at digital
    full scale, which can confuse some players/editors.
    Returns True on success, False on failure.
    '''
    ffmpeg = shutil.which('ffmpeg')
    if not ffmpeg:
        print('ffmpeg not found; cannot convert to WAV')
        return False

    sr = str(sample_rate)
    # Use ffmpeg's default SW resampler (soxr may not be available in all builds).
    af = 'aresample={},alimiter=level=false:limit=-0.5dB'.format(sr)

    cmd = [
        ffmpeg, '-y', '-i', amr_file,
        '-ar', sr, '-ac', '1',
        '-map_metadata', '-1',
        '-fflags', '+bitexact',
        '-af', af,
        wav_file
    ]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            print('ffmpeg conversion failed:')
            print(result.stderr[-1000:])
            return False
        print('Converted to WAV: {}'.format(wav_file))
        return True
    except Exception as e:
        print('Error running ffmpeg: {}'.format(e))
        return False


def analyze_wav_level(wav_file):
    '''
    Return a simple audio-level summary for a WAV file.
    Returns a dict with duration, rms, peak, dbfs and a silence flag.
    If the file cannot be analyzed, returns None.
    '''
    try:
        with wave.open(wav_file, 'rb') as w:
            nframes = w.getnframes()
            rate = w.getframerate()
            sw = w.getsampwidth()
            ch = w.getnchannels()
            if nframes == 0 or sw not in (1, 2, 3, 4):
                return None
            data = w.readframes(nframes)
        fmt = {1: 'b', 2: 'h', 3: 'i', 4: 'i'}.get(sw)
        if sw == 3:
            # 24-bit stored in 32-bit int, shift to align MSB
            samples = []
            for i in range(nframes * ch):
                b = data[i*3:(i+1)*3]
                v = int.from_bytes(b, byteorder='little', signed=True) << 8
                samples.append(v >> 8)  # sign-extend
        else:
            samples = list(struct.unpack('<{}{}'.format(nframes * ch, fmt), data))
        peak = max(abs(s) for s in samples)
        rms = math.sqrt(sum(s * s for s in samples) / len(samples))
        full_scale = 2 ** ((sw * 8) - 1)
        dbfs = 20 * math.log10(rms / full_scale) if rms > 0 else -999.0
        duration = nframes / rate
        return {
            'duration': duration,
            'rms': rms,
            'peak': peak,
            'dbfs': dbfs,
            'silent': dbfs < -60.0,
        }
    except Exception as e:
        logging.debug('Could not analyze {}: {}'.format(wav_file, e))
        return None


def mix_wavs(wav_files, out_wav, sample_rate, delays=None):
    '''
    Mix multiple mono WAV files into one multichannel WAV using ffmpeg.
    Each input becomes one output channel; shorter inputs are padded with
    silence so all channels have the same length.
    If delays is provided, each channel is delayed by the given number of
    samples (at the target sample rate) so flows are aligned by their absolute
    pcap capture time.
    Returns True on success, False on failure.
    '''
    ffmpeg = shutil.which('ffmpeg')
    if not ffmpeg:
        print('ffmpeg not found; cannot mix WAVs')
        return False

    if not wav_files:
        return False

    if delays is None:
        delays = [0] * len(wav_files)
    elif len(delays) != len(wav_files):
        delays = list(delays) + [0] * (len(wav_files) - len(delays))

    # Determine the longest input in samples at the target sample rate,
    # including any alignment delay.
    max_samples = 0
    valid_files = []
    valid_delays = []
    for idx, wf in enumerate(wav_files):
        try:
            with wave.open(wf, 'rb') as w:
                frames = w.getnframes()
                rate = w.getframerate()
                ch = w.getnchannels()
            if ch == 0:
                continue
            # Scale frame count to target sample rate (integer, rounded up).
            scaled = int(math.ceil(frames * sample_rate / rate))
            total = scaled + delays[idx]
            if total > max_samples:
                max_samples = total
            valid_files.append(wf)
            valid_delays.append(delays[idx])
        except Exception as e:
            logging.debug('Skipping {} for mix: {}'.format(wf, e))

    if not valid_files:
        print('No valid WAV files to mix')
        return False

    # Build filter_complex: resample each input to mono at target rate, delay,
    # pad, then merge channels.
    inputs = []
    pads = []
    merge = []
    for i, wf in enumerate(valid_files):
        inputs.extend(['-i', wf])
        delay_ms = int(round(valid_delays[i] * 1000.0 / sample_rate))
        if delay_ms > 0:
            delay_str = 'adelay=delays={ms}|{ms}:all=1,'.format(ms=delay_ms)
        else:
            delay_str = ''
        pads.append('[{i}:a]aresample={sr},aformat=channel_layouts=mono,{delay_str}apad=whole_len={max_samples}[a{i}]'.format(
            i=i, sr=sample_rate, delay_str=delay_str, max_samples=max_samples))
        merge.append('[a{}]'.format(i))

    filter_complex = ';'.join(pads) + ';' + ''.join(merge) + 'amerge=inputs={}[out]'.format(len(valid_files))

    cmd = [
        ffmpeg, '-y',
    ] + inputs + [
        '-filter_complex', filter_complex,
        '-map', '[out]',
        '-map_metadata', '-1',
        '-fflags', '+bitexact',
        out_wav
    ]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            print('ffmpeg mix failed:')
            print(result.stderr[-1000:])
            return None
        print('Mixed multichannel WAV: {}'.format(out_wav))
        return {
            'channels': len(valid_files),
            'duration': max_samples / sample_rate,
            'out_wav': out_wav,
        }
    except Exception as e:
        print('Error running ffmpeg mix: {}'.format(e))
        return None


def mix_to_mono(wav_files, out_wav, sample_rate, delays=None):
    '''
    Mix multiple mono WAV files down to a single mono WAV using ffmpeg.
    If delays is provided, each input is delayed by the given number of
    samples so streams are aligned by pcap capture time before summing.
    Returns True on success, False on failure.
    '''
    ffmpeg = shutil.which('ffmpeg')
    if not ffmpeg:
        print('ffmpeg not found; cannot mix to mono')
        return False

    if not wav_files:
        return False

    if delays is None:
        delays = [0] * len(wav_files)
    elif len(delays) != len(wav_files):
        delays = list(delays) + [0] * (len(wav_files) - len(delays))

    valid_files = []
    valid_delays = []
    for wf, d in zip(wav_files, delays):
        try:
            with wave.open(wf, 'rb') as w:
                if w.getnchannels() == 0:
                    continue
            valid_files.append(wf)
            valid_delays.append(d)
        except Exception as e:
            logging.debug('Skipping {} for mono mix: {}'.format(wf, e))

    if not valid_files:
        print('No valid WAV files to mix to mono')
        return False

    try:
        if len(valid_files) == 1:
            cmd = [
                ffmpeg, '-y', '-i', valid_files[0],
                '-ar', str(sample_rate), '-ac', '1',
                '-map_metadata', '-1', '-fflags', '+bitexact',
                out_wav
            ]
        else:
            inputs = []
            filter_parts = []
            for i, wf in enumerate(valid_files):
                inputs.extend(['-i', wf])
                delay_ms = int(round(valid_delays[i] * 1000.0 / sample_rate))
                filters = 'aresample={sr},aformat=channel_layouts=mono'.format(sr=sample_rate)
                if delay_ms > 0:
                    filters += ',adelay=delays={ms}|{ms}:all=1'.format(ms=delay_ms)
                filter_parts.append('[{i}:a]{filters}[a{i}]'.format(
                    i=i, filters=filters))
            merge = ''.join('[a{}]'.format(i) for i in range(len(valid_files)))
            filter_complex = ';'.join(filter_parts) + ';' + merge + \
                'amix=inputs={}:duration=longest:normalize=0[aout]'.format(len(valid_files))
            cmd = [
                ffmpeg, '-y',
            ] + inputs + [
                '-filter_complex', filter_complex,
                '-map', '[aout]',
                '-ar', str(sample_rate), '-ac', '1',
                '-map_metadata', '-1', '-fflags', '+bitexact',
                out_wav
            ]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            print('ffmpeg mono mix failed:')
            print(result.stderr[-1000:])
            return False
        print('Mixed direction WAV: {}'.format(out_wav))
        return True
    except Exception as e:
        print('Error running ffmpeg mono mix: {}'.format(e))
        return False


def join_to_stereo(left_wav, right_wav, out_wav, sample_rate):
    '''
    Join two mono WAV files into a single stereo WAV file.
    Left channel = left_wav, right channel = right_wav.
    Shorter inputs are padded with silence so the stereo output is as long as
    the longest input.
    Returns True on success, False on failure.
    '''
    ffmpeg = shutil.which('ffmpeg')
    if not ffmpeg:
        print('ffmpeg not found; cannot join stereo')
        return False

    try:
        with wave.open(left_wav, 'rb') as w:
            left_frames = w.getnframes()
        with wave.open(right_wav, 'rb') as w:
            right_frames = w.getnframes()
        max_samples = max(left_frames, right_frames)
    except Exception as e:
        print('Could not read input WAVs for stereo join: {}'.format(e))
        return False

    filter_complex = (
        '[0:a]apad=whole_len={max_samples}[left];'
        '[1:a]apad=whole_len={max_samples}[right];'
        '[left][right]join=inputs=2:channel_layout=stereo[aout]'
    ).format(max_samples=max_samples)

    cmd = [
        ffmpeg, '-y',
        '-i', left_wav, '-i', right_wav,
        '-filter_complex', filter_complex,
        '-map', '[aout]',
        '-ar', str(sample_rate),
        '-map_metadata', '-1', '-fflags', '+bitexact',
        out_wav
    ]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            print('ffmpeg stereo join failed:')
            print(result.stderr[-1000:])
            return False
        print('Stereo direction WAV: {}'.format(out_wav))
        return True
    except Exception as e:
        print('Error running ffmpeg stereo join: {}'.format(e))
        return False


def _parse_endpoint(endpoint_str):
    '''Parse an "ip:port" string, returning (ip, port).'''
    ip, port = endpoint_str.rsplit(':', 1)
    return ip, int(port)


def generate_direction_mixes(results, outdir, sample_rate):
    '''
    For every RTP endpoint (ip:port) seen in the results, create:
      - ipport_<ip>_<port>_incoming.wav : all streams received at that socket
      - ipport_<ip>_<port>_outgoing.wav : all streams sent from that socket
      - ipport_<ip>_<port>_stereo.wav   : stereo file (incoming left, outgoing right)
      - mixed_all_endpoints.wav         : one multichannel file with one channel
                                          per endpoint+direction, aligned by pcap time
      - mixed_all_endpoints_channels.txt: channel map for the multichannel file
    All files are aligned to the earliest pcap time of the endpoint's flows.
    Returns a dict mapping 'ip:port' -> {'incoming': path, 'outgoing': path, 'stereo': path}
    plus a special '__combined__' key with the multichannel mix and channel map.
    '''
    # Parse discrete src/dst endpoints from the human-readable strings.
    for r in results:
        if not r.get('wavfile'):
            continue
        if 'src_endpoint' not in r:
            r['src_endpoint'] = r['src']
        if 'dst_endpoint' not in r:
            r['dst_endpoint'] = r['dst']

    endpoints = set()
    for r in results:
        if r.get('wavfile'):
            endpoints.add(r['src_endpoint'])
            endpoints.add(r['dst_endpoint'])

    mixes = {}
    # Track each endpoint+direction that will become a channel in the combined mix.
    combined_channels = []

    for ep in sorted(endpoints):
        incoming = [r for r in results if r.get('wavfile') and r.get('dst_endpoint') == ep]
        outgoing = [r for r in results if r.get('wavfile') and r.get('src_endpoint') == ep]
        if not incoming and not outgoing:
            continue

        relevant = incoming + outgoing
        first_times = [r['first_pcap_time'] for r in relevant if r.get('first_pcap_time') is not None]
        if not first_times:
            continue
        t0 = min(first_times)

        ep_safe = sanitize_filename(ep.replace(':', '_'))
        incoming_wav = None
        outgoing_wav = None

        if incoming:
            wavs = [r['wavfile'] for r in incoming]
            delays = [int(round((r['first_pcap_time'] - t0) * sample_rate))
                      if r.get('first_pcap_time') is not None else 0 for r in incoming]
            incoming_wav = os.path.join(outdir, 'ipport_{}_incoming.wav'.format(ep_safe))
            if mix_to_mono(wavs, incoming_wav, sample_rate, delays=delays):
                mixes.setdefault(ep, {})['incoming'] = incoming_wav
                combined_channels.append({
                    'endpoint': ep,
                    'direction': 'incoming',
                    'wavfile': incoming_wav,
                    't0': t0,
                })

        if outgoing:
            wavs = [r['wavfile'] for r in outgoing]
            delays = [int(round((r['first_pcap_time'] - t0) * sample_rate))
                      if r.get('first_pcap_time') is not None else 0 for r in outgoing]
            outgoing_wav = os.path.join(outdir, 'ipport_{}_outgoing.wav'.format(ep_safe))
            if mix_to_mono(wavs, outgoing_wav, sample_rate, delays=delays):
                mixes.setdefault(ep, {})['outgoing'] = outgoing_wav
                combined_channels.append({
                    'endpoint': ep,
                    'direction': 'outgoing',
                    'wavfile': outgoing_wav,
                    't0': t0,
                })

        if incoming_wav and outgoing_wav and os.path.isfile(incoming_wav) and os.path.isfile(outgoing_wav):
            stereo_wav = os.path.join(outdir, 'ipport_{}_stereo.wav'.format(ep_safe))
            if join_to_stereo(incoming_wav, outgoing_wav, stereo_wav, sample_rate):
                mixes[ep]['stereo'] = stereo_wav

    # Build one multichannel WAV with one channel per endpoint+direction.
    if len(combined_channels) >= 2:
        global_t0 = min(ch['t0'] for ch in combined_channels)
        wav_files = []
        delays = []
        for ch in combined_channels:
            wav_files.append(ch['wavfile'])
            delays.append(int(round((ch['t0'] - global_t0) * sample_rate)))
        combined_wav = os.path.join(outdir, 'mixed_all_endpoints.wav')
        mix_info = mix_wavs(wav_files, combined_wav, sample_rate, delays=delays)
        if mix_info:
            channels_file = os.path.join(outdir, 'mixed_all_endpoints_channels.txt')
            try:
                with open(channels_file, 'w', encoding='utf-8') as f:
                    f.write('# Channel map for mixed_all_endpoints.wav\n')
                    f.write('# Left = incoming to the socket, Right = outgoing from the socket (when stereo).\n')
                    f.write('# Each line: Channel N = <endpoint> <direction>\n')
                    for idx, ch in enumerate(combined_channels, start=1):
                        f.write('Channel {} = {} {}\n'.format(idx, ch['endpoint'], ch['direction']))
                print('Wrote channel map: {}'.format(channels_file))
            except Exception as e:
                print('Could not write channel map: {}'.format(e))
            mixes['__combined__'] = {
                'wavfile': combined_wav,
                'channels_file': channels_file,
                'channels': len(combined_channels),
            }

    return mixes


def write_flow_pcap(packets, ssrc, pt, out_pcap):
    '''
    Write all original packets belonging to a single RTP flow
    (matching SSRC and payload type) to a new pcap file.
    Returns True on success, False on failure.
    '''
    from scapy.layers.inet import IP
    flow_packets = []
    for packet in packets:
        if UDP not in packet or IP not in packet:
            continue
        data = bytes(packet[UDP].payload)
        rtp = parse_rtp(data)
        if rtp is None:
            continue
        if rtp['sourcesync'] == ssrc and rtp['payload_type'] == pt:
            flow_packets.append(packet)
    if not flow_packets:
        return False
    try:
        wrpcap(out_pcap, flow_packets)
        return True
    except Exception as e:
        logging.debug('Could not write pcap {}: {}'.format(out_pcap, e))
        return False


def parse_rtp(data):
    '''
    Parse raw RTP bytes and return a dict with header fields and payload bytes.
    Handles RTP header extensions, CSRC list and padding.
    Returns None if data is not a valid RTP packet.
    '''
    if len(data) < 12:
        return None

    version = data[0] >> 6
    if version != 2:
        return None

    padding = (data[0] >> 5) & 0x01
    extension = (data[0] >> 4) & 0x01
    cc = data[0] & 0x0F
    marker = (data[1] >> 7) & 0x01
    payload_type = data[1] & 0x7F
    sequence = struct.unpack('!H', data[2:4])[0]
    timestamp = struct.unpack('!I', data[4:8])[0]
    ssrc = struct.unpack('!I', data[8:12])[0]

    offset = 12 + cc * 4
    if extension:
        if len(data) < offset + 4:
            return None
        # ext_len is the number of 32-bit words in the extension
        ext_len = struct.unpack('!H', data[offset + 2:offset + 4])[0]
        offset += 4 + ext_len * 4

    payload_end = len(data)
    if padding:
        if offset >= payload_end:
            return None
        pad_len = data[-1]
        if pad_len == 0:
            pad_len = 1
        payload_end -= pad_len

    if offset > payload_end:
        return None

    payload = data[offset:payload_end]

    return {
        'version': version,
        'padding': padding,
        'extension': extension,
        'cc': cc,
        'marker': marker,
        'payload_type': payload_type,
        'sequence': sequence,
        'timestamp': timestamp,
        'sourcesync': ssrc,
        'payload': payload,
    }


def get_flow_endpoints(packets, ssrc, pt):
    '''
    Determine the most common source/destination IP:port for a given RTP flow.
    Returns a tuple (src_ip, src_port, dst_ip, dst_port) or None if not found.
    '''
    from scapy.layers.inet import IP
    endpoints = {}
    for packet in packets:
        if UDP not in packet or IP not in packet:
            continue
        data = bytes(packet[UDP].payload)
        rtp = parse_rtp(data)
        if rtp is None:
            continue
        if rtp['sourcesync'] != ssrc or rtp['payload_type'] != pt:
            continue
        src = (packet[IP].src, packet[UDP].sport)
        dst = (packet[IP].dst, packet[UDP].dport)
        key = (src, dst)
        endpoints[key] = endpoints.get(key, 0) + 1
    if not endpoints:
        return None
    (src, dst), _ = max(endpoints.items(), key=lambda x: x[1])
    return (src[0], src[1], dst[0], dst[1])


def sanitize_filename(text):
    '''Replace characters that are unsafe in file names.'''
    return re.sub(r'[^\w\-\.]', '_', str(text))


def get_samples_per_frame(codec):
    '''Return the RTP timestamp increment for one frame of the given codec.'''
    if codec == 'amr':
        return 160  # 8 kHz, 20 ms
    elif codec == 'amr-wb':
        return 320  # 16 kHz, 20 ms
    elif codec == 'evs':
        return 320  # assume 16 kHz, 20 ms
    return 320


def write_silence_frame(outfile, codec):
    '''
    Write one frame of silence in RFC 4867 storage format.
    ffmpeg on some systems drops AMR NO_DATA frames, so AMR uses a mode-0
    frame with zeroed speech bits. AMR-WB uses NO_DATA, which decodes to
    silence in ffmpeg.
    '''
    if codec == 'amr':
        # Mode 0, good frame, reserved bits zero, followed by 12 zero bytes.
        outfile.write(b'\x04' + b'\x00' * 12)
    elif codec == 'amr-wb':
        # NO_DATA: TOC byte only.
        outfile.write(b'\x7c')
    else:
        # EVS: write a minimal silence payload (primary 2.8 kbps, TOC 0x00).
        outfile.write(b'\x00' * 7)


def extract_flow(rtp_packets, ssrc, pt, codec, framing, outfile):
    '''
    Extract a single RTP flow to the given output file.
    Preserves silent periods by inserting silence frames for RTP timestamp
    gaps (DTX / missing packets) and by replacing SID frames with silence so
    ffmpeg does not drop them.
    Returns a dict with extraction statistics.
    '''
    global num_bad_frames, num_control_frames, fn
    num_bad_frames = 0
    num_control_frames = 0
    fn = -1

    seen_seq = set()
    selected = []
    for rtp in rtp_packets:
        if rtp['sourcesync'] == ssrc and rtp['payload_type'] == pt:
            if rtp['sequence'] not in seen_seq:
                seen_seq.add(rtp['sequence'])
                selected.append(rtp)
    # Sort primarily by RTP sequence number, timestamp as tie-breaker.
    selected.sort(key=lambda x: (x['sequence'], x['timestamp']))

    samples_per_frame = get_samples_per_frame(codec)
    inserted_silence_frames = 0
    # Cap silence insertion to avoid exploding file size on timestamp resets or
    # wrap-around anomalies. Up to 5 seconds of silence per gap covers real
    # DTX/hold periods; a single missing packet with a huge timestamp jump is
    # treated as a stream discontinuity and capped much lower.
    max_silence_per_gap = 250  # 250 frames = 5 seconds
    single_packet_jump_cap = 50  # 50 frames = 1 second

    with open(outfile, 'wb') as ofile:
        if codec == 'amr':
            ofile.write('#!AMR\n'.encode())
        elif codec == 'amr-wb':
            ofile.write('#!AMR-WB\n'.encode())
        else:
            ofile.write('#!EVS_MC1.0\n'.encode())
            ofile.write(b'\x00\x00\x00\x01')

        prev_ts = None
        prev_seq = None
        for rtp in selected:
            # Insert silence for RTP timestamp gaps (DTX / missing packets).
            if prev_ts is not None:
                gap = rtp['timestamp'] - prev_ts
                # Handle 32-bit RTP timestamp wrap-around.
                if gap < 0:
                    gap += 2 ** 32
                if gap > samples_per_frame * 1.5:
                    raw_missing = int(round((gap - samples_per_frame) / samples_per_frame))
                    seq_diff = (rtp['sequence'] - prev_seq) & 0xFFFF
                    cap = max_silence_per_gap
                    # A single missing packet cannot represent more than ~1s of silence.
                    if seq_diff == 1 and raw_missing > single_packet_jump_cap:
                        cap = single_packet_jump_cap
                    missing = min(max(1, raw_missing), cap)
                    for _ in range(missing):
                        write_silence_frame(ofile, codec)
                        inserted_silence_frames += 1
            prev_ts = rtp['timestamp']
            prev_seq = rtp['sequence']

            if framing == 'ietf':
                storePayloadIetf(ofile, codec, rtp['payload'])
            else:
                storePayloadIu(ofile, codec, rtp['payload'])

    return {
        'ssrc': ssrc,
        'pt': pt,
        'codec': codec,
        'frames': len(selected),
        'inserted_silence_frames': inserted_silence_frames,
        'bad_frames': num_bad_frames,
        'control_frames': num_control_frames,
        'first_ts': selected[0]['timestamp'] if selected else None,
        'last_ts': selected[-1]['timestamp'] if selected else None,
        'first_pcap_time': selected[0]['pcap_time'] if selected else None,
    }


def storePayloadIetf(outfile, codec, payload):
    '''
    Writes the codec payload inside rtp_packet to the output file as
    described in section 5 of RFC4864.
    :param outfile: output file
    :type: FILE handler
    :param codec: codec name
    :type: str
    :param payload: codec payload inside RTP packet
    :type: bytes
    :rtype: void
    '''
    global num_bad_frames

    if len(payload) < 2:
        logging.debug('RTP payload too short: {}'.format(len(payload)))
        return

    if codec == 'amr' or codec == 'amr-wb':
        if codec == 'amr':
            # Total number of bits for modes 0 to 8 (Tables 2 and A.1b in TS26.101)
            codec_ft = [95, 103, 118, 134, 148, 159, 204, 244, 39]
            sid_ft = 8
        else:  # amr-wb
            # Total number of bits for modes 0 to 9 (Table 2 in TS26.201)
            # Note: this table matches the RTP payload sizes in amrwb_payload_sizes.
            # FT 8 -> 477 bits (payload 61), FT 9 -> 40 bits SID (payload 7).
            codec_ft = [132, 177, 253, 285, 317, 365, 397, 461, 477, 40]
            sid_ft = 9

        # Bandwidth-efficient header layout (RFC 4867):
        #   CMR(4) | F(1) | FT(4) | Q(1) | speech data ... | padding
        # The first byte contains CMR(4)+F(1)+FT(3 MSB).
        # The second byte contains FT(1 LSB)+Q(1)+speech(6).
        header = struct.unpack('!H', payload[0:2])[0]
        ft = (header >> 7) & 0x0F   # FT is 4 bits
        q = (header >> 6) & 0x01
        if q == 0:
            num_bad_frames += 1

        # Replace SID frames with a silence frame. Some ffmpeg builds cannot
        # decode SID and silently drop them, which removes silent/DTX periods
        # from the WAV.
        if ft == sid_ft:
            write_silence_frame(outfile, codec)
            return

        if ft >= len(codec_ft):
            logging.debug('Invalid AMR-WB FT: {} (max {})'.format(ft, len(codec_ft) - 1))
            return

        # Build storage-format TOC byte: 0 | FT(4) | Q(1) | 00
        toc_byte = (ft << 3) | (q << 2)
        bitline = bitarray(endian='big')
        bitline.frombytes(toc_byte.to_bytes(1, byteorder='big'))

        # Load the speech bits, skipping the CMR byte and the first 2 bits of
        # the second byte (FT LSB and Q).
        buf = bitarray(endian='big')
        buf.frombytes(payload[1:])
        buf = buf[2:]

        # Remove padding bits so we keep exactly the speech frame size.
        if len(buf) >= codec_ft[ft]:
            buf = buf[:codec_ft[ft]]
        else:
            logging.debug('Short payload: FT={} expected {} bits got {}'.format(
                ft, codec_ft[ft], len(buf)))

        bitline += buf  # TOC + codec frame
        bitline.tofile(outfile)  # 0 padding is done by bitarray to achieve byte alignment
        logging.debug('FT={} Q={} bits={}'.format(ft, q, len(bitline)))

    else:  # evs
        # We do NOT distinguish between pure EVS and EVS AMR-WB IO mode
        is_io_modes = [0, -1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0]  # 0 = EVS, 1 = EVS AMR-WB IO, -1 = ambiguous (Table A.1 in 3GPP TS 26.445)
        evs_payload_sizes = [6, 7, 17, 18, 20, 23, 24, 32, 33, 36, 40, 41, 46, 50, 58, 60, 61, 80, 120, 160, 240, 320]
        toc = [b'\x0C', b'\x00', b'0', b'\x01', b'\x02', b'1', b'\x03', b'2', b'\x04', b'3', b'4', b'\x05', b'5', b'6', b'7', b'8', b'\x06', b'\x07', b'\x08', b'\x09', b'\x0A', b'\x0B']
        is_io = is_io_modes[evs_payload_sizes.index(len(payload))]
        if is_io == 0:  # evs
            outfile.write(toc[evs_payload_sizes.index(len(payload))])
            outfile.write(payload)
            logging.debug('EVS\ttoc: {}\tlen: {}'.format(toc[evs_payload_sizes.index(len(payload))], len(payload)))
        elif is_io == 1:  # evs amr-wb io -> remove CMR bits
            toc_byte = bitarray(endian='big')
            toc_byte.frombytes(toc[evs_payload_sizes.index(len(payload))])
            buf = bitarray(endian='big')
            buf.frombytes(payload)
            buf = toc_byte + buf[3:]
            buf.tofile(outfile)
            logging.debug('AMR-WB IO\ttoc: {}\tlen: {}'.format(toc_byte, len(payload)))
        else:  # ambigous case
            bit0 = struct.unpack('!B', payload[0:1])[0] & 0x80
            if bit0 == 0:    # it is evs primary 2.8kbps
                outfile.write(toc[1] + payload)
                logging.debug('EVS 2.8\ttoc: {}\tlen: {}'.format(toc[1], len(payload)))
            else:  # it is evs amr-wb io sid in header-full with one CMR byte
                buf = bitarray(endian='big')
                buf.frombytes(payload)
                buf = buf[8:]  # remove CMR byte but leave TOC byte
                buf.tofile(outfile)
                logging.debug('EVS AMR-WB IO SID'.format(toc[1], len(payload)))


def storePayloadIu(outfile, codec, amrpl):
    '''
    Writes the codec payload inside rtp_packet to the output file as
    described in section 5 of RFC4864.
    :param outfile: output file
    :type: FILE handler
    :param codec: codec name
    :type: str
    :param amrpl: codec payload inside RTP packet
    :type: bytes
    :rtype: void
    '''
    global fn, num_control_frames, num_bad_frames

    if codec == 'amr':
        # Total number of bits for modes 0 to 8 (Tables 2 and A.1b in TS26.101)
        codec_ft = [95, 103, 118, 134, 148, 159, 204, 244, 39]
        sid_ft = 8
        # this dictionary maps expected IUFH payload lengths (in octets) to AMR-WB modes
        codec_ft_map = {
            12: 0,
            13: 1,
            15: 2,
            17: 3,
            19: 4,
            20: 5,
            26: 6,
            31: 7,
            5: 8
        }
    else:  # amr-wb
        # Total number of bits for modes 0 to 9 (Table 2 in TS26.201)
        codec_ft = [132, 177, 253, 285, 317, 365, 397, 461, 477, 40]
        sid_ft = 9
        # this dictionary maps expected IUFH payload lengths (in octets) to AMR-WB modes
        codec_ft_map = {
            17: 0,
            23: 1,
            32: 2,
            36: 3,
            40: 4,
            46: 5,
            50: 6,
            58: 7,
            60: 8,
            5: 9
        }

    if len(amrpl) < 2:
        return

    header = struct.unpack('!H', amrpl[0:2])[0]  # only the first two octets contain relevant info
    pdu_type = header & 0xF000
    frame_number = header & 0x0F00
    fqc = header & 0x00C0
    isvalid = False
    if pdu_type == 0xE000:  # PDU type 14 -> Control frame
        num_control_frames += 1
    else:  # skip repeated frames
        if fn != frame_number:
            fn = frame_number
            isvalid = True
    if isvalid == True:
        q = 1 if fqc == 0 else 0
        hdr_len = 4 if pdu_type == 0 else 3
        ft_index = len(amrpl) - hdr_len
        if ft_index not in codec_ft_map:
            logging.debug('Unknown Iu payload length: {}'.format(len(amrpl)))
            return
        ft = codec_ft_map[ft_index]

        # Replace SID frames with a silence frame to avoid ffmpeg dropping them.
        if ft == sid_ft:
            write_silence_frame(outfile, codec)
            return

        if q == 0:
            num_bad_frames += 1
        toc_bits = (ft << 3) | (q << 2)
        toc = toc_bits.to_bytes(1, byteorder='big')
        bitline = bitarray(endian='big')
        bitline.frombytes(toc)
        # load the bits
        buf = bitarray(endian='big')
        buf.frombytes(amrpl[hdr_len:])
        if len(buf) >= codec_ft[ft]:
            buf = buf[:codec_ft[ft]]
        bitline += buf  # toc + codec frame
        bitline.tofile(outfile)  # 0 padding is done by bitarray to achieve byte alignment
    else:
        logging.debug('Invalid Iu frame')


def guessCodec(rtp_packets, framing):
    '''
    Parses the RTP payloads to try to guess the codec used.
    The function exits as soon as the codec is resolved.
    :param rtp_packets: list of parsed RTP packets
    :type: list of dict
    :param framing: 'ietf' or 'iu'
    :type: str
    :rtype: str or None
    '''
    syncsrcid = -1
    ptype = -1

    # Count RTP flows and choose the busiest one.
    flows = Counter((p['sourcesync'], p['payload_type']) for p in rtp_packets)
    if not flows:
        return None

    if FORCED_PAYLOAD_TYPE is not None:
        candidates = [(k, v) for k, v in flows.items() if k[1] == FORCED_PAYLOAD_TYPE]
        if candidates:
            syncsrcid, ptype = max(candidates, key=lambda x: x[1])[0]
        else:
            syncsrcid, ptype = max(flows.items(), key=lambda x: x[1])[0]
    else:
        syncsrcid, ptype = max(flows.items(), key=lambda x: x[1])[0]

    count = 100  # number of packet samples to check
    packets_codec = {'amr': 0, 'amr-wb': 0, 'evs': 0}

    ietf_sets = {
        'amr': set(amr_payload_sizes),
        'amr-wb': set(amrwb_payload_sizes),
        'evs': set(evs_payload_sizes),
    }
    iu_sets = {
        'amr': set(amr_payload_sizes_iupt0 + amr_payload_sizes_iupt1),
        'amr-wb': set(amrwb_payload_sizes_iupt0 + amrwb_payload_sizes_iupt1),
        'evs': set(),
    }
    size_sets = ietf_sets if framing == 'ietf' else iu_sets

    for packet in rtp_packets:
        if count <= 0:
            break
        if packet['sourcesync'] != syncsrcid or packet['payload_type'] != ptype:
            continue

        payload_len = len(packet['payload'])
        classified = False

        if framing == 'ietf':
            # For AMR/AMR-WB, verify FT matches payload size.
            if payload_len >= 2:
                header = struct.unpack('!H', packet['payload'][0:2])[0]
                ft = (header >> 7) & 0x0F
                if payload_len in ietf_sets['amr']:
                    if ft < 9 and payload_len == amr_payload_sizes[ft]:
                        packets_codec['amr'] += 1
                        classified = True
                if not classified and payload_len in ietf_sets['amr-wb']:
                    expected = amrwb_payload_sizes[ft] if ft < len(amrwb_payload_sizes) else None
                    if expected is not None and abs(payload_len - expected) <= 2:
                        packets_codec['amr-wb'] += 1
                        classified = True
                if not classified and payload_len in ietf_sets['evs']:
                    packets_codec['evs'] += 1
                    classified = True
        else:  # iu
            if payload_len in iu_sets['amr']:
                packets_codec['amr'] += 1
                classified = True
            elif payload_len in iu_sets['amr-wb']:
                packets_codec['amr-wb'] += 1
                classified = True

        if classified:
            count -= 1

    print('AMR samples: {}, AMR-WB samples: {}, EVS samples: {}'.format(
        packets_codec['amr'], packets_codec['amr-wb'], packets_codec['evs']))
    if packets_codec['amr'] > 0 and packets_codec['amr-wb'] == packets_codec['evs'] == 0:
        return 'amr'
    if packets_codec['amr-wb'] > 0 and packets_codec['amr'] == packets_codec['evs'] == 0:
        return 'amr-wb'
    if packets_codec['evs'] > 0:
        return 'evs'
    return None   # could not guess


def select_flow(rtp_packets, codec, framing, sdp_hints=None):
    '''
    Select the busiest RTP flow. If a codec is specified, prefer flows whose
    payload sizes match that codec, and further prefer flows whose PT was
    announced in SDP for this codec.
    '''
    if not rtp_packets:
        return None

    flows = Counter((p['sourcesync'], p['payload_type']) for p in rtp_packets)
    if not flows:
        return None

    if FORCED_PAYLOAD_TYPE is not None:
        candidates = {k: v for k, v in flows.items() if k[1] == FORCED_PAYLOAD_TYPE}
        if candidates:
            flows = candidates

    if codec != 'guess':
        expected_sizes = get_expected_payload_sizes(codec, framing)
        # Keep flows that have at least one payload size matching the codec.
        matching = {}
        for flow, count in flows.items():
            for p in rtp_packets:
                if (p['sourcesync'], p['payload_type']) == flow:
                    if len(p['payload']) in expected_sizes:
                        matching[flow] = count
                        break
        if matching:
            flows = matching
        else:
            logging.warning('No flow matches codec {}; using busiest flow'.format(codec))

        # If SDP announced this codec, prefer PTs that match the SDP.
        if sdp_hints:
            hinted_pts = {pt for pt, c in sdp_hints.items() if c == codec}
            hinted_flows = {k: v for k, v in flows.items() if k[1] in hinted_pts}
            if hinted_flows:
                flows = hinted_flows
                logging.debug('Preferring SDP-hinted PTs for {}: {}'.format(codec, hinted_pts))

    return max(flows.items(), key=lambda x: x[1])[0]


def usage():
    '''Prints command line'''
    print('Usage: pcap_parser.py -i pcap_file [options]')
    print('Options:')
    print('  -c codec       codec [amr, amr-wb, evs], default = guess')
    print('  -f framing     framing [ietf, iu], default = ietf')
    print('  -o file        single output file (legacy mode)')
    print('  -d dir         output directory for all flows (auto-created if omitted)')
    print('  --wav          also convert each output to WAV using ffmpeg')
    print('  -ar rate       WAV output sample rate in Hz (default: 16000)')
    print('  --pcaps        also write one pcap per RTP flow (ssrc/pt)')
    print('  --mix          also create one multichannel WAV from all flow WAVs')
    print('  --direction-mix  create per-IP:port incoming/outgoing/stereo WAV mixes')
    print('  --no-align-time  with --mix: start all channels at time 0 instead of aligning by pcap time')
    print('If -o is used, only the busiest matching flow is extracted.')
    print('Otherwise, every matching RTP flow is extracted to its own file.')


def determine_flow_codecs(flows, rtp_packets, framing, sdp_hints, codec='guess'):
    '''
    Return a dict mapping each flow to the most likely codec.
    If a codec is explicitly specified globally, all flows use it.
    If guessing, use SDP hints and payload sizes per flow.
    '''
    flow_codecs = {}

    # Explicit codec overrides everything, including possibly wrong SDP.
    if codec != 'guess':
        for flow in flows:
            flow_codecs[flow] = codec
        return flow_codecs

    ietf_sets = {
        'amr': set(amr_payload_sizes),
        'amr-wb': set(amrwb_payload_sizes),
        'evs': set(evs_payload_sizes),
    }
    iu_sets = {
        'amr': set(amr_payload_sizes_iupt0 + amr_payload_sizes_iupt1),
        'amr-wb': set(amrwb_payload_sizes_iupt0 + amrwb_payload_sizes_iupt1),
        'evs': set(),
    }
    size_sets = ietf_sets if framing == 'ietf' else iu_sets

    for flow in flows:
        ssrc, pt = flow
        # Trust SDP first.
        if sdp_hints and pt in sdp_hints:
            flow_codecs[flow] = sdp_hints[pt]
            continue
        # Otherwise vote by payload sizes in this flow.
        votes = {'amr': 0, 'amr-wb': 0, 'evs': 0}
        for p in rtp_packets:
            if (p['sourcesync'], p['payload_type']) != flow:
                continue
            plen = len(p['payload'])
            for cname, sizes in size_sets.items():
                if plen in sizes:
                    votes[cname] += 1
        best = max(votes, key=votes.get)
        if votes[best] > 0:
            flow_codecs[flow] = best
        else:
            flow_codecs[flow] = None
    return flow_codecs


def generate_report(outdir, args, packets, rtp_packets, flows, flow_codecs,
                    results, sip_dialogs, flow_labels, direction_mixes=None):
    '''
    Write a human-friendly README.md report into the output directory.
    Includes run details, SIP call summary, RTP flow table, pairing guide,
    per-IP direction mixes, diagrams and listening instructions.
    '''
    report_path = os.path.join(outdir, 'README.md')
    result_by_flow = {(r['ssrc'], r['pt']): r for r in results}
    relevant_call_ids = {label_info['call_id']
                         for flow, label_info in flow_labels.items()
                         if label_info.get('call_id')}

    lines = []
    lines.append('# Extraction Report')
    lines.append('')
    lines.append('## Run Details')
    lines.append('')
    lines.append('- **Input pcap:** `{}`'.format(args.infile))
    lines.append('- **Output folder:** `{}`'.format(outdir))
    lines.append('- **Run time:** {}'.format(datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    lines.append('- **Command:** `python3 {}`'.format(' '.join(sys.argv)))
    lines.append('- **Total packets in pcap:** {}'.format(len(packets)))
    lines.append('- **RTP packets found:** {}'.format(len(rtp_packets)))
    lines.append('- **Extracted flows:** {}'.format(len(results)))
    lines.append('')

    # SIP summary
    lines.append('## SIP Call Summary')
    lines.append('')
    if sip_dialogs:
        relevant_dialogs = {cid: d for cid, d in sip_dialogs.items() if cid in relevant_call_ids}
        if relevant_dialogs:
            lines.append('| Call-ID | Caller (A-party) | Callee (B-party) | A media | B media |')
            lines.append('|---|---|---|---|---|')
            for cid, dialog in relevant_dialogs.items():
                caller = dialog.get('caller')
                callee = dialog.get('callee')
                caller_str = '{}'.format(caller.get('uri')) if caller else 'unknown'
                callee_str = '{}'.format(callee.get('uri')) if callee else 'unknown'
                a_media = dialog.get('caller_media')
                b_media = dialog.get('callee_media')
                a_media_str = '{}:{} (PTs: {})'.format(
                    a_media.get('connection') or caller.get('ip') if caller else '?',
                    a_media.get('media_port') or '?',
                    ', '.join(str(p) for p in a_media.get('pts', []))) if a_media else 'not seen'
                b_media_str = '{}:{} (PTs: {})'.format(
                    b_media.get('connection') or callee.get('ip') if callee else '?',
                    b_media.get('media_port') or '?',
                    ', '.join(str(p) for p in b_media.get('pts', []))) if b_media else 'not seen'
                lines.append('| `{}` | {} | {} | {} | {} |'.format(
                    cid, caller_str, callee_str, a_media_str, b_media_str))
            lines.append('')
        else:
            lines.append('SIP signaling was found but could not be matched to the extracted RTP flows.')
            lines.append('')
    else:
        lines.append('No SIP signaling was found in this capture. RTP direction labels are unavailable.')
        lines.append('')

    # RTP flows
    lines.append('## Extracted RTP Flows')
    lines.append('')
    lines.append('| SSRC | PT | Codec | Direction | Source -> Destination | Frames | Duration | Level | Output | Wireshark filter |')
    lines.append('|---|---|---|---|---|---|---|---|---|---|')
    for flow in flows:
        ssrc, pt = flow
        r = result_by_flow.get(flow)
        if not r:
            continue
        codec = r.get('codec', 'unknown')
        direction = flow_labels.get(flow, {}).get('direction', 'Unknown')
        level = r.get('level')
        if level:
            level_str = '{:.1f} dBFS'.format(level['dbfs'])
            if level['silent']:
                level_str += ' [SILENT]'
            duration_str = '{:.2f}s'.format(level['duration'])
        else:
            level_str = '-'
            duration_str = '-'
        out_file = r.get('wavfile') or r.get('outfile')
        out_name = os.path.basename(out_file)
        ws_filter = '`rtp.ssrc == 0x{:08x}`'.format(ssrc)
        frame_str = str(r.get('frames'))
        if r.get('inserted_silence_frames'):
            frame_str += ' (+{} silence)'.format(r['inserted_silence_frames'])
        lines.append('| `0x{:08x}` | {} | {} | {} | {} -> {} | {} | {} | {} | `{}` | {} |'.format(
            ssrc, pt, codec, direction, r.get('src'), r.get('dst'),
            frame_str, duration_str, level_str, out_name, ws_filter))
    lines.append('')

    # Pairing / direction guide
    if sip_dialogs and relevant_call_ids:
        lines.append('## Call Direction Guide')
        lines.append('')
        lines.append('This table maps each Call-ID to the captured RTP directions.')
        lines.append('')
        lines.append('| Call-ID | A -> B flow | B -> A flow | Notes |')
        lines.append('|---|---|---|---|')
        for cid in sorted(relevant_call_ids):
            dialog = sip_dialogs.get(cid)
            if not dialog:
                continue
            a_to_b = []
            b_to_a = []
            for flow, label_info in flow_labels.items():
                if label_info.get('call_id') != cid:
                    continue
                r = result_by_flow.get(flow)
                if not r:
                    continue
                out_name = os.path.basename(r.get('wavfile') or r.get('outfile'))
                if label_info['direction'] == 'A -> B':
                    a_to_b.append('`{}`'.format(out_name))
                elif label_info['direction'] == 'B -> A':
                    b_to_a.append('`{}`'.format(out_name))
            a_to_b_str = '<br>'.join(a_to_b) if a_to_b else '-'
            b_to_a_str = '<br>'.join(b_to_a) if b_to_a else '-'
            notes = []
            if not a_to_b:
                notes.append('A->B direction not captured')
            if not b_to_a:
                notes.append('B->A direction not captured')
            notes_str = '; '.join(notes) if notes else 'Both directions present' if a_to_b and b_to_a else 'unknown'
            lines.append('| `{}` | {} | {} | {} |'.format(cid, a_to_b_str, b_to_a_str, notes_str))
        lines.append('')

    # Diagrams
    lines.append('## SIP + RTP Diagram')
    lines.append('')
    if sip_dialogs and relevant_call_ids:
        lines.append('```mermaid')
        lines.append('sequenceDiagram')
        shown_participants = set()
        for cid in sorted(relevant_call_ids):
            dialog = sip_dialogs.get(cid)
            if not dialog or not dialog.get('caller') or not dialog.get('callee'):
                continue
            cid_suffix = sanitize_filename(cid[-24:])
            a_label = 'A_{}'.format(cid_suffix)
            b_label = 'B_{}'.format(cid_suffix)
            a_desc = dialog['caller'].get('uri') or dialog['caller']['ip']
            b_desc = dialog['callee'].get('uri') or dialog['callee']['ip']
            if a_label not in shown_participants:
                lines.append('    participant {} as "A-party<br/>{}"'.format(a_label, a_desc))
                shown_participants.add(a_label)
            if b_label not in shown_participants:
                lines.append('    participant {} as "B-party<br/>{}"'.format(b_label, b_desc))
                shown_participants.add(b_label)

            # SIP signalling (first few messages)
            sip_msgs = [m for m in dialog['messages'] if m.get('method') in ('INVITE', 'ACK', 'BYE') or
                        (not m.get('is_request') and m.get('status_code'))]
            for msg in sip_msgs[:6]:
                if msg['is_request']:
                    arrow = '{}->>{}: {}'.format(a_label if msg['src_ip'] == dialog['caller']['ip'] else b_label,
                                                 b_label if msg['dst_ip'] == dialog['callee']['ip'] else a_label,
                                                 msg.get('method') or 'SIP')
                else:
                    arrow = '{}->>{}: {} {}'.format(b_label if msg['src_ip'] == dialog['callee']['ip'] else a_label,
                                                     a_label if msg['dst_ip'] == dialog['caller']['ip'] else b_label,
                                                     msg.get('status_code') or '', msg.get('method') or '')
                lines.append('    {}'.format(arrow.strip()))

            # RTP streams
            for flow, label_info in flow_labels.items():
                if label_info.get('call_id') != cid:
                    continue
                r = result_by_flow.get(flow)
                if not r:
                    continue
                fname = os.path.basename(r.get('wavfile') or r.get('outfile'))
                if label_info['direction'] == 'A -> B':
                    lines.append('    {}->>{}: RTP SSRC 0x{:08x} ({})'.format(
                        a_label, b_label, flow[0], fname))
                elif label_info['direction'] == 'B -> A':
                    lines.append('    {}->>{}: RTP SSRC 0x{:08x} ({})'.format(
                        b_label, a_label, flow[0], fname))
        lines.append('```')
        lines.append('')

        # ASCII direction overview
        lines.append('### ASCII Overview')
        lines.append('')
        for cid in sorted(relevant_call_ids):
            dialog = sip_dialogs.get(cid)
            if not dialog:
                continue
            caller = dialog.get('caller')
            callee = dialog.get('callee')
            if not caller or not callee:
                continue
            lines.append('- **Call-ID:** `{}`'.format(cid))
            for flow, label_info in flow_labels.items():
                if label_info.get('call_id') != cid:
                    continue
                r = result_by_flow.get(flow)
                if not r:
                    continue
                fname = os.path.basename(r.get('wavfile') or r.get('outfile'))
                if label_info['direction'] == 'A -> B':
                    lines.append('  ```')
                    lines.append('  A-party ({})  --[SSRC 0x{:08x}, {}]-->  B-party ({})'.format(
                        caller['ip'], flow[0], fname, callee['ip']))
                    lines.append('  ```')
                elif label_info['direction'] == 'B -> A':
                    lines.append('  ```')
                    lines.append('  B-party ({})  --[SSRC 0x{:08x}, {}]-->  A-party ({})'.format(
                        callee['ip'], flow[0], fname, caller['ip']))
                    lines.append('  ```')
            lines.append('')
    else:
        lines.append('No SIP signaling available, so no A/B party diagram can be drawn.')
        lines.append('')

    # Per-endpoint direction mixes
    if direction_mixes:
        lines.append('## Per-Endpoint (IP:port) Direction Mixes')
        lines.append('')
        lines.append('For every RTP socket (IP:port), the traffic **entering** that socket and **leaving** that socket has been mixed into separate mono files. A stereo file is also provided (incoming = left channel, outgoing = right channel).')
        lines.append('')
        lines.append('| Endpoint (IP:port) | Incoming (received) | Outgoing (sent) | Stereo |')
        lines.append('|---|---|---|---|')
        for ep in sorted(direction_mixes.keys()):
            if ep == '__combined__':
                continue
            files = direction_mixes[ep]
            inc = os.path.basename(files['incoming']) if files.get('incoming') else '-'
            out = os.path.basename(files['outgoing']) if files.get('outgoing') else '-'
            ster = os.path.basename(files['stereo']) if files.get('stereo') else '-'
            lines.append('| `{}` | `{}` | `{}` | `{}` |'.format(ep, inc, out, ster))
        lines.append('')
        lines.append('**Listening tip:** Open the stereo file in Audacity. The left ear is everything that socket **heard**; the right ear is everything that socket **said**.')
        lines.append('')

        combined = direction_mixes.get('__combined__')
        if combined:
            lines.append('### Single combined endpoint-direction mix')
            lines.append('')
            lines.append('`{}` is a single multichannel WAV that contains every endpoint+direction on its own channel, aligned by pcap capture time.'.format(os.path.basename(combined['wavfile'])))
            lines.append('')
            lines.append('Open it in Audacity and choose **Split to mono tracks**. Each track is named in `{}`.'.format(os.path.basename(combined['channels_file'])))
            lines.append('')
            lines.append('| Channel | Endpoint (IP:port) | Direction |')
            lines.append('|---|---|---|')
            try:
                with open(combined['channels_file'], 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        # Format: "Channel N = ep direction"
                        parts = line.split('=', 1)
                        if len(parts) != 2:
                            continue
                        chan = parts[0].strip()
                        rest = parts[1].strip().rsplit(' ', 1)
                        if len(rest) == 2:
                            ep_name, direction = rest
                            lines.append('| `{}` | `{}` | `{}` |'.format(chan, ep_name, direction))
            except Exception:
                pass
            lines.append('')
            lines.append('**Tip for non-technical users:** channel order = one endpoint after another; for each endpoint the incoming channel comes first, then the outgoing channel.')
            lines.append('')

    # How to listen
    lines.append('## How to Listen / Use the Files')
    lines.append('')
    lines.append('1. **Per-flow audio:** Each row in the RTP Flows table has a playable audio file.')
    lines.append('   - `.wav` files are standard 16-bit PCM WAV.')
    lines.append('   - `.amr`, `.awb`, `.evs` files are raw codec payloads.')
    if any(r.get('level', {}).get('silent') for r in results if r.get('level')):
        lines.append('   - Flows marked **SILENT** contain no speech in that direction.')
    if args.mix:
        lines.append('2. **Combined view:** Open `mixed_all_flows.wav` in Audacity.')
        lines.append('   - Audacity will ask how to import the multichannel file; choose **Split to mono tracks**.')
        if args.no_align_time:
            lines.append('   - All channels start at time 0.')
        else:
            lines.append('   - Channels are aligned by pcap capture time (like Wireshark RTP player), so a flow that started later begins with silence.')
        lines.append('   - Each track corresponds to one SSRC in the order shown in the RTP Flows table above.')
    if args.pcaps:
        lines.append('{}. **Wireshark analysis:** Use the `.pcap` files or the `rtp.ssrc == 0x...` filter from the table.'.format(
            3 if args.mix else 2))
    lines.append('')

    try:
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        print('Report written: {}'.format(report_path))
    except Exception as e:
        print('Could not write report: {}'.format(e))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', action='store', dest='codec', default='guess', help='codec [amr, amr-wb, evs], default = guess codec')
    parser.add_argument('-f', action='store', dest='framing', default='ietf', help='framing [ietf, iu], default = ietf')
    parser.add_argument('-i', action='store', dest='infile', help='PCAP file to scan')
    parser.add_argument('-o', action='store', dest='outfile', default=None, help='Single output audio file (busiest flow only)')
    parser.add_argument('-d', action='store', dest='outdir', default=None, help='Output directory for all flows')
    parser.add_argument('--wav', action='store_true', dest='wav', default=False, help='Also convert output(s) to WAV using ffmpeg')
    parser.add_argument('-ar', '--sample-rate', action='store', dest='sample_rate', type=int,
                        default=16000, help='WAV output sample rate in Hz (default: 16000)')
    parser.add_argument('--pcaps', action='store_true', dest='pcaps', default=False,
                        help='Also write one pcap per RTP flow (ssrc/pt) for Wireshark analysis')
    parser.add_argument('--mix', action='store_true', dest='mix', default=False,
                        help='Also create one multichannel WAV mixing all flow WAVs (one channel per flow)')
    parser.add_argument('--no-align-time', action='store_true', dest='no_align_time', default=False,
                        help='When mixing, start all channels at time 0 instead of aligning by pcap capture time')
    parser.add_argument('--direction-mix', action='store_true', dest='direction_mix', default=False,
                        help='Create per-IP:port direction mixes (incoming/outgoing/stereo)')

    args = parser.parse_args()

    # Mixing requires per-flow WAVs.
    if args.mix and not args.wav:
        args.wav = True
    if args.direction_mix and not args.wav:
        args.wav = True

    logging.basicConfig(filename='pcap_parser.log', filemode='w', level=logging.DEBUG)

    if not args.infile:
        usage()
        exit(-1)

    if args.codec not in supported_codecs:
        print('Unsupported codec: {}'.format(args.codec))
        exit(-2)
    codec = args.codec

    if args.framing != 'ietf' and args.framing != 'iu':
        print('Unsupported framing: {}'.format(args.framing))
        exit(-2)
    framing = args.framing

    packets = rdpcap(args.infile)  # read packets from pcap or pcapng file

    if len(packets) <= 0:
        print('Empty or invalid input file (not pcap?)')
        exit(-3)
    else:
        print('Number of packets read from pcap: {}'.format(len(packets)))

    # Parse all RTP packets first.
    rtp_packets = []
    for packet in packets:
        if UDP not in packet:
            continue
        data = bytes(packet[UDP].payload)
        rtp = parse_rtp(data)
        if rtp is not None:
            # Attach the pcap capture timestamp so flows can be aligned by
            # wall-clock time in the mixed output.
            rtp['pcap_time'] = float(packet.time)
            rtp_packets.append(rtp)

    if not rtp_packets:
        print('No RTP packets found in pcap')
        exit(-4)

    print('Number of RTP packets found: {}'.format(len(rtp_packets)))

    # Extract codec/payload-type hints from SIP/SDP if present.
    sdp_hints = extract_sdp_hints(packets)
    if sdp_hints:
        logging.debug('SDP hints: {}'.format(sdp_hints))
        print('SDP hints: {}'.format(sdp_hints))

    # Determine global codec if specified or guessed.
    if codec == 'guess':
        hinted_codecs = set(sdp_hints.values())
        if len(hinted_codecs) == 1 and hinted_codecs.issubset(set(supported_codecs)):
            codec = hinted_codecs.pop()
            print('Guessed codec from SDP: {}'.format(codec))
        else:
            codec = guessCodec(rtp_packets, framing)
            if codec is None:
                print('Unable to guess the codec used.')
                exit(-4)

    # Minimum frames for a flow to be considered in multi-flow mode.
    MIN_FRAMES = 10

    # Build the set of all RTP flows.
    all_flows = sorted(set((p['sourcesync'], p['payload_type']) for p in rtp_packets))

    # Filter flows by codec if we know it.
    if codec != 'guess':
        expected_sizes = get_expected_payload_sizes(codec, framing)
        matching_flows = []
        for flow in all_flows:
            ssrc, pt = flow
            # When the codec is explicitly forced, do NOT require the SDP to
            # agree. PCAPs with misleading/wrong SDP (e.g. declared AMR but
            # actually EVS) would otherwise be rejected.
            if sdp_hints and pt in sdp_hints and sdp_hints[pt] == codec:
                pass  # SDP agrees, fine
            # Accept if payload sizes match and we have enough frames.
            flow_packets = [p for p in rtp_packets
                            if (p['sourcesync'], p['payload_type']) == flow]
            if len(flow_packets) < MIN_FRAMES:
                continue
            if any(len(p['payload']) in expected_sizes for p in flow_packets):
                matching_flows.append(flow)
        if not matching_flows:
            print('No RTP flows match codec {}'.format(codec))
            exit(-4)
        flows = matching_flows
    else:
        # In guess mode, filter out tiny flows.
        flows = [f for f in all_flows
                 if sum(1 for p in rtp_packets
                        if (p['sourcesync'], p['payload_type']) == f) >= MIN_FRAMES]

    # Determine codec per flow.
    flow_codecs = determine_flow_codecs(flows, rtp_packets, framing, sdp_hints, codec)

    # Parse SIP signaling to label RTP directions and build a report.
    sip_messages = extract_sip_messages(packets)
    sip_dialogs = build_sip_dialogs(sip_messages)
    flow_labels = label_flows_with_sip(flows, packets, sip_dialogs)
    if sip_dialogs:
        print('SIP dialogs found: {}'.format(len(sip_dialogs)))

    # Single-flow legacy mode.
    if args.outfile:
        selected_flow = select_flow(rtp_packets, codec, framing, sdp_hints)
        if selected_flow is None:
            print('No suitable RTP flow found')
            exit(-4)
        ssrc, pt = selected_flow
        flow_codec = flow_codecs.get(selected_flow, codec)
        print('Selected RTP flow: SSRC=0x{:08x}, PT={}'.format(ssrc, pt))
        stats = extract_flow(rtp_packets, ssrc, pt, flow_codec, framing, args.outfile)
        print('Extracted: codec={}, frames={}, bad={}'.format(
            flow_codec, stats['frames'], stats['bad_frames']))
        if args.wav:
            base, _ = os.path.splitext(args.outfile)
            wav_file = base + '.wav'
            if convert_to_wav(args.outfile, wav_file, args.sample_rate):
                print('WAV output ready: {}'.format(wav_file))
                level = analyze_wav_level(wav_file)
                if level:
                    note = ' [SILENT / very low level]' if level['silent'] else ''
                    print('  duration={:.2f}s  peak={}  RMS={:.1f} dBFS{}'.format(
                        level['duration'], level['peak'], level['dbfs'], note))
            else:
                print('WAV conversion failed')
                exit(-5)
        if args.pcaps:
            base, _ = os.path.splitext(args.outfile)
            pcap_file = base + '.pcap'
            if write_flow_pcap(packets, ssrc, pt, pcap_file):
                print('RTP flow pcap: {}'.format(pcap_file))
            else:
                print('pcap write failed for flow')
        exit(0)

    # Multi-flow mode.
    if args.outdir:
        outdir = args.outdir
    else:
        basename = os.path.splitext(os.path.basename(args.infile))[0]
        outdir = '{}_extracted_{}'.format(basename, datetime.now().strftime('%Y%m%d_%H%M%S'))

    if not os.path.exists(outdir):
        os.makedirs(outdir)
    print('Output directory: {}'.format(outdir))

    results = []
    for flow in flows:
        ssrc, pt = flow
        flow_codec = flow_codecs.get(flow)
        if flow_codec is None:
            print('Skipping flow SSRC=0x{:08x}, PT={}: unknown codec'.format(ssrc, pt))
            continue

        endpoints = get_flow_endpoints(packets, ssrc, pt)
        if endpoints:
            src_ip, src_port, dst_ip, dst_port = endpoints
        else:
            src_ip = src_port = dst_ip = dst_port = 'unknown'

        ext = {'amr': 'amr', 'amr-wb': 'awb', 'evs': 'evs'}.get(flow_codec, 'bin')
        filename = 'ssrc0x{:08x}_{}_{}:{}_to_{}:{}.{}'.format(
            ssrc, flow_codec, sanitize_filename(src_ip), src_port,
            sanitize_filename(dst_ip), dst_port, ext)
        outfile = os.path.join(outdir, filename)

        stats = extract_flow(rtp_packets, ssrc, pt, flow_codec, framing, outfile)
        stats.update({
            'src': '{}:{}'.format(src_ip, src_port),
            'dst': '{}:{}'.format(dst_ip, dst_port),
            'outfile': outfile,
        })

        if args.wav:
            wavfile = outfile + '.wav'
            if flow_codec == 'evs':
                ok = convert_evs_to_wav(rtp_packets, ssrc, pt, wavfile, args.sample_rate)
            else:
                ok = convert_to_wav(outfile, wavfile, args.sample_rate)
            if ok:
                stats['wavfile'] = wavfile
                stats['level'] = analyze_wav_level(wavfile)
            else:
                stats['wavfile'] = None
                stats['level'] = None

        if args.pcaps:
            base, _ = os.path.splitext(outfile)
            pcapfile = base + '.pcap'
            if write_flow_pcap(packets, ssrc, pt, pcapfile):
                stats['pcapfile'] = pcapfile
                print('Wrote RTP flow pcap: {}'.format(pcapfile))
            else:
                stats['pcapfile'] = None

        results.append(stats)

    # Print summary.
    print('\n=== Extraction Summary ===')
    print('{:>18} {:>6} {:>8} {:>24} -> {:<24} {:>8} {:>12} {:>8} {}'.format(
        'SSRC', 'PT', 'Codec', 'Source', 'Destination', 'Frames', 'Level', 'Extras', 'Output'))
    print('-' * 150)
    for r in results:
        ssrc_hex = '0x{:08x}'.format(r['ssrc'])
        out = r.get('wavfile') or r['outfile']
        extras = []
        if r.get('wavfile'):
            extras.append('wav')
        if r.get('pcapfile'):
            extras.append('pcap')
        extras_str = ' '.join(extras) if extras else '-'
        level = r.get('level')
        if level:
            level_str = '{:.1f} dBFS'.format(level['dbfs'])
            if level['silent']:
                level_str += ' [SILENT]'
        else:
            level_str = '-'
        frame_note = str(r['frames'])
        if r.get('inserted_silence_frames'):
            frame_note += ' (+{} silence)'.format(r['inserted_silence_frames'])
        print('{:>18} {:>6} {:>8} {:>24} -> {:<24} {:>8} {:>12} {:>8} {}'.format(
            ssrc_hex, r['pt'], r['codec'], r['src'], r['dst'], frame_note, level_str, extras_str, out))
    print('\nTotal flows extracted: {}'.format(len(results)))
    if args.wav:
        print('All WAV files are {:.0f} Hz, 16-bit mono PCM.'.format(args.sample_rate))

    if args.mix:
        wav_files = [r['wavfile'] for r in results if r.get('wavfile')]
        if wav_files:
            mixed_wav = os.path.join(outdir, 'mixed_all_flows.wav')
            # By default align channels by pcap capture time, like Wireshark's
            # RTP player. --no-align-time disables this and starts all at 0.
            if args.no_align_time:
                mix_info = mix_wavs(wav_files, mixed_wav, args.sample_rate)
            else:
                first_times = [r['first_pcap_time'] for r in results
                               if r.get('wavfile') and r.get('first_pcap_time') is not None]
                if first_times:
                    min_first_time = min(first_times)
                    delays = []
                    for r in results:
                        if not r.get('wavfile'):
                            continue
                        t0 = r.get('first_pcap_time')
                        if t0 is not None:
                            delay_samples = int(round((t0 - min_first_time) * args.sample_rate))
                            delays.append(delay_samples)
                        else:
                            delays.append(0)
                    mix_info = mix_wavs(wav_files, mixed_wav, args.sample_rate, delays=delays)
                else:
                    mix_info = mix_wavs(wav_files, mixed_wav, args.sample_rate)
            if mix_info:
                print('Mixed all {} flow(s) into: {}'.format(mix_info['channels'], mix_info['out_wav']))
                print('  duration={:.2f}s  channels={}'.format(
                    mix_info['duration'], mix_info['channels']))
            else:
                print('Failed to create mixed WAV')
        else:
            print('No WAV files available to mix')

    direction_mixes = {}
    if args.direction_mix:
        direction_mixes = generate_direction_mixes(results, outdir, args.sample_rate)
        if direction_mixes:
            print('\n=== Per-Endpoint (IP:port) Direction Mixes ===')
            for ep in sorted(direction_mixes.keys()):
                if ep == '__combined__':
                    continue
                files = direction_mixes[ep]
                print('  {}:'.format(ep))
                if files.get('incoming'):
                    print('    incoming -> {}'.format(os.path.basename(files['incoming'])))
                if files.get('outgoing'):
                    print('    outgoing -> {}'.format(os.path.basename(files['outgoing'])))
                if files.get('stereo'):
                    print('    stereo   -> {} (incoming=left, outgoing=right)'.format(
                        os.path.basename(files['stereo'])))
            combined = direction_mixes.get('__combined__')
            if combined:
                print('\nCombined endpoint-direction mix:')
                print('  WAV:    {}'.format(os.path.basename(combined['wavfile'])))
                print('  Map:    {}'.format(os.path.basename(combined['channels_file'])))
                print('  Channels: {}'.format(combined['channels']))
        else:
            print('No per-IP direction mixes generated')

    # Write a human-friendly README report into the output folder.
    generate_report(outdir, args, packets, rtp_packets, flows, flow_codecs,
                    results, sip_dialogs, flow_labels, direction_mixes)

    exit(0)
