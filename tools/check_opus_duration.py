#!/usr/bin/env python3
"""
Analyze Opus packet duration from actual data file
"""

import struct
import sys
import os

def analyze_opus_toc(first_byte):
    """Analyze Opus TOC (Table of Contents) byte"""
    
    # TOC byte structure:
    # Bits 7-3: Configuration (5 bits)
    # Bit 2: Stereo flag (1 bit) 
    # Bits 1-0: Frame count code (2 bits)
    
    config = (first_byte >> 3) & 0x1F  # Configuration (5 bits)
    stereo = (first_byte >> 2) & 0x01  # Stereo flag (1 bit)
    frame_count_code = first_byte & 0x03  # Frame count code (2 bits)
    
    # Determine frame duration based on config
    # Opus configuration table (RFC 6716):
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
    
    # Determine frame count
    if frame_count_code == 0:
        frame_count = 1
    elif frame_count_code == 1:
        frame_count = 2
    elif frame_count_code == 2:
        frame_count = 2  # VBR
    else:
        frame_count = "Multiple"
    
    return {
        'config': config,
        'stereo': 'Stereo' if stereo else 'Mono',
        'frame_count': frame_count,
        'frame_duration': frame_duration,
        'bandwidth': bandwidth,
        'toc_byte': f"0x{first_byte:02x}"
    }

def analyze_opus_file(file_path):
    """Analyze actual Opus data file"""
    
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found.")
        return
    
    print(f"Analyzing Opus packets from: {file_path}")
    print("=" * 50)
    
    with open(file_path, 'rb') as f:
        packet_count = 0
        frame_durations = {}
        
        # Analyze first few packets
        for i in range(5):  # Check first 5 packets
            # Read length
            length_bytes = f.read(4)
            if len(length_bytes) < 4:
                break
            
            packet_length = struct.unpack('<I', length_bytes)[0]
            
            # Read packet data
            packet_data = f.read(packet_length)
            if len(packet_data) < packet_length:
                break
            
            packet_count += 1
            
            if len(packet_data) > 0:
                first_byte = packet_data[0]
                analysis = analyze_opus_toc(first_byte)
                
                # Count frame durations
                duration = analysis['frame_duration']
                frame_durations[duration] = frame_durations.get(duration, 0) + 1
                
                print(f"Packet {packet_count}:")
                print(f"  Length: {packet_length} bytes")
                print(f"  TOC byte: {analysis['toc_byte']}")
                print(f"  Config: {analysis['config']}")
                print(f"  Frame duration: {analysis['frame_duration']}")
                print(f"  Bandwidth: {analysis['bandwidth']}")
                print(f"  Channels: {analysis['stereo']}")
                print(f"  First bytes: {packet_data[:8].hex()}")
                print()
        
        # Count total packets
        f.seek(0)
        total_packets = 0
        while True:
            length_bytes = f.read(4)
            if len(length_bytes) < 4:
                break
            
            packet_length = struct.unpack('<I', length_bytes)[0]
            f.seek(packet_length, 1)  # Skip packet data
            total_packets += 1
        
        print("=" * 50)
        print("SUMMARY:")
        print(f"Total packets: {total_packets}")
        
        if frame_durations:
            most_common_duration = max(frame_durations, key=frame_durations.get)
            print(f"Frame duration: {most_common_duration}")
            
            # Calculate total time
            duration_ms = int(most_common_duration.replace('ms', ''))
            total_time_ms = total_packets * duration_ms
            total_time_sec = total_time_ms / 1000.0
            
            print(f"Calculated duration: {total_packets} packets × {duration_ms}ms = {total_time_sec:.2f} seconds")
        else:
            print("Could not determine frame duration")

def main():
    if len(sys.argv) != 2:
        print("Usage: python check_opus_duration.py <opus_data_file>")
        print("Example: python check_opus_duration.py yyy.dat")
        sys.exit(1)
    
    file_path = sys.argv[1]
    analyze_opus_file(file_path)

if __name__ == "__main__":
    main()
