#!/usr/bin/env python3
"""
Analyze Opus packets to understand their structure and content.
This helps identify silence frames, audio frames, and VBR patterns.
"""

import struct
import sys
import os

def analyze_opus_packet(packet_data):
    """Analyze a single Opus packet to determine its type and characteristics"""
    
    if len(packet_data) == 0:
        return "Empty packet"
    
    # Opus packet structure analysis
    first_byte = packet_data[0]
    
    # TOC (Table of Contents) byte analysis
    config = (first_byte >> 3) & 0x1F  # Configuration (5 bits)
    stereo = (first_byte >> 2) & 0x01  # Stereo flag (1 bit)
    frame_count_code = first_byte & 0x03  # Frame count code (2 bits)
    
    # Determine frame count
    if frame_count_code == 0:
        frame_count = 1
    elif frame_count_code == 1:
        frame_count = 2
    elif frame_count_code == 2:
        frame_count = 2  # VBR
    else:
        frame_count = "Multiple"
    
    # Determine frame duration based on config (RFC 6716)
    frame_durations = ["10ms", "20ms", "40ms", "60ms"]
    frame_idx = config % 4
    
    if config >= 0 and config <= 3:
        frame_duration = frame_durations[frame_idx]
        bandwidth = "SILK NB (8kHz)"
    elif config >= 4 and config <= 7:
        frame_duration = frame_durations[frame_idx]
        bandwidth = "SILK MB (12kHz)"
    elif config >= 8 and config <= 11:
        frame_duration = frame_durations[frame_idx]
        bandwidth = "SILK WB (16kHz)"
    elif config >= 12 and config <= 15:
        frame_duration = frame_durations[frame_idx]
        bandwidth = "Hybrid SWB (24kHz)"
    elif config >= 16 and config <= 19:
        frame_duration = frame_durations[frame_idx]
        bandwidth = "Hybrid FB (48kHz)"
    elif config >= 20 and config <= 23:
        celt_durations = ["2.5ms", "5ms", "10ms", "20ms"]
        frame_duration = celt_durations[frame_idx]
        bandwidth = "CELT NB (8kHz)"
    elif config >= 24 and config <= 27:
        celt_durations = ["2.5ms", "5ms", "10ms", "20ms"]
        frame_duration = celt_durations[frame_idx]
        bandwidth = "CELT NB (8kHz)"
    elif config >= 28 and config <= 31:
        celt_durations = ["2.5ms", "5ms", "10ms", "20ms"]
        frame_duration = celt_durations[frame_idx]
        bandwidth = "CELT WB (16kHz)"
    else:
        frame_duration = "Unknown"
        bandwidth = "Unknown"
    
    # Analyze packet content to guess if it's silence
    is_likely_silence = False
    if len(packet_data) <= 10:  # Very small packets are often silence
        is_likely_silence = True
    elif len(packet_data) >= 3:
        # Check for common silence patterns
        if packet_data[:3] == b'\xb8\xff\xfe':  # Common Opus silence pattern
            is_likely_silence = True
    
    return {
        'size': len(packet_data),
        'config': config,
        'stereo': 'Stereo' if stereo else 'Mono',
        'frame_count': frame_count,
        'frame_duration': frame_duration,
        'likely_silence': is_likely_silence,
        'first_bytes': packet_data[:min(8, len(packet_data))].hex()
    }

def analyze_opus_file(file_path):
    """Analyze all packets in the Opus data file"""
    
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found.")
        return
    
    print(f"Analyzing Opus packets in: {file_path}")
    print("=" * 60)
    
    with open(file_path, 'rb') as f:
        packet_num = 0
        silence_count = 0
        audio_count = 0
        size_distribution = {}
        
        while True:
            # Read length
            length_bytes = f.read(4)
            if len(length_bytes) < 4:
                break
            
            packet_length = struct.unpack('<I', length_bytes)[0]
            
            # Read packet data
            packet_data = f.read(packet_length)
            if len(packet_data) < packet_length:
                print(f"Warning: Incomplete packet {packet_num + 1}")
                break
            
            packet_num += 1
            
            # Analyze packet
            analysis = analyze_opus_packet(packet_data)
            
            # Count by type
            if analysis['likely_silence']:
                silence_count += 1
            else:
                audio_count += 1
            
            # Size distribution
            size_range = f"{(analysis['size'] // 10) * 10}-{(analysis['size'] // 10) * 10 + 9}"
            size_distribution[size_range] = size_distribution.get(size_range, 0) + 1
            
            # Show detailed info for first few, last few, and some middle packets
            show_detail = (packet_num <= 5 or 
                          packet_num >= packet_num - 5 or 
                          packet_num % 20 == 0)
            
            if show_detail or packet_num <= 10:
                status = "SILENCE" if analysis['likely_silence'] else "AUDIO"
                print(f"Packet {packet_num:3d}: {analysis['size']:3d} bytes, "
                      f"{analysis['stereo']}, {analysis['frame_duration']}, "
                      f"Config={analysis['config']:2d}, {status}")
                if packet_num <= 3:
                    print(f"           First bytes: {analysis['first_bytes']}")
        
        print("\n" + "=" * 60)
        print("SUMMARY:")
        print(f"Total packets: {packet_num}")
        print(f"Silence packets: {silence_count} ({silence_count/packet_num*100:.1f}%)")
        print(f"Audio packets: {audio_count} ({audio_count/packet_num*100:.1f}%)")
        
        print(f"\nSize distribution:")
        for size_range in sorted(size_distribution.keys(), key=lambda x: int(x.split('-')[0])):
            count = size_distribution[size_range]
            percentage = count / packet_num * 100
            print(f"  {size_range:>8} bytes: {count:3d} packets ({percentage:4.1f}%)")
        
        print(f"\nVBR Analysis:")
        print("- Small packets (≤10 bytes): Likely silence or very low volume")
        print("- Medium packets (11-50 bytes): Low complexity audio or quiet speech")
        print("- Large packets (>50 bytes): Complex audio, music, or loud speech")
        print("\nThis is normal VBR behavior - Opus adapts bitrate to audio complexity!")

def main():
    if len(sys.argv) != 2:
        print("Usage: python analyze_opus_packets.py <opus_data_file>")
        print("Example: python analyze_opus_packets.py yyy.data")
        sys.exit(1)
    
    file_path = sys.argv[1]
    analyze_opus_file(file_path)

if __name__ == "__main__":
    main()
