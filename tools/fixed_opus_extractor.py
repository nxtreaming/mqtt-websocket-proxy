#!/usr/bin/env python3
"""
Fixed Opus packet extractor from OGG files.
This correctly extracts pure Opus packets without OGG container metadata.
Creates the custom format: 4 bytes length + pure Opus packet data.
"""

import struct
import sys
import os

def extract_opus_packets(ogg_file_path, output_file_path):
    """Extract pure Opus packets from OGG file, skipping container metadata"""
    
    with open(ogg_file_path, 'rb') as input_file:
        with open(output_file_path, 'wb') as output_file:
            
            packet_count = 0
            header_packets_skipped = 0
            current_packet = b''
            
            while True:
                # Read OGG page header
                page_header = input_file.read(27)  # OGG page header is 27 bytes
                if len(page_header) < 27:
                    break
                
                # Check OGG signature
                if page_header[:4] != b'OggS':
                    print(f"Invalid OGG signature at position {input_file.tell() - 27}, stopping")
                    break
                
                # Parse page header
                version = page_header[4]
                header_type = page_header[5]
                granule_pos = struct.unpack('<Q', page_header[6:14])[0]
                serial_no = struct.unpack('<I', page_header[14:18])[0]
                page_seq = struct.unpack('<I', page_header[18:22])[0]
                checksum = struct.unpack('<I', page_header[22:26])[0]
                page_segments = page_header[26]
                
                # Read segment table
                segment_table = input_file.read(page_segments)
                if len(segment_table) < page_segments:
                    break
                
                # Calculate total page data size
                page_data_size = sum(segment_table)
                
                # Read page data
                page_data = input_file.read(page_data_size)
                if len(page_data) < page_data_size:
                    break
                
                # Parse packets from page data
                data_offset = 0
                for i, segment_size in enumerate(segment_table):
                    if data_offset + segment_size > len(page_data):
                        break
                    
                    segment_data = page_data[data_offset:data_offset + segment_size]
                    data_offset += segment_size
                    
                    # Accumulate packet data
                    current_packet += segment_data
                    
                    # Check if this is the end of a packet (segment size < 255)
                    if segment_size < 255:
                        # We have a complete packet
                        if len(current_packet) > 0:
                            # Skip Opus header packets (first two packets)
                            if header_packets_skipped < 2:
                                header_packets_skipped += 1
                                print(f"Skipping header packet {header_packets_skipped}: {len(current_packet)} bytes")
                                
                                # Debug: show first few bytes of header packets
                                if len(current_packet) >= 8:
                                    header_preview = current_packet[:8].hex()
                                    print(f"  Header preview: {header_preview}")
                                
                                current_packet = b''
                                continue
                            
                            # This is an audio data packet - extract pure Opus data
                            opus_packet = current_packet
                            
                            # Verify this looks like an Opus packet
                            if len(opus_packet) > 0:
                                # Opus packets typically start with specific patterns
                                # But we'll accept any non-header packet as valid
                                
                                packet_length = len(opus_packet)
                                
                                # Write 4-byte length (little endian)
                                output_file.write(struct.pack('<I', packet_length))
                                
                                # Write pure Opus packet data (no OGG container metadata)
                                output_file.write(opus_packet)
                                
                                packet_count += 1
                                print(f"Extracted Opus packet {packet_count}: {packet_length} bytes")
                                
                                # Debug: show first few bytes of audio packets
                                if packet_count <= 3 and len(opus_packet) >= 4:
                                    packet_preview = opus_packet[:4].hex()
                                    print(f"  Packet preview: {packet_preview}")
                        
                        # Reset for next packet
                        current_packet = b''
            
            print(f"Successfully extracted {packet_count} pure Opus packets to {output_file_path}")
            return packet_count > 0

def verify_output_file(output_file_path):
    """Verify the output file format and show some statistics"""
    
    if not os.path.exists(output_file_path):
        print("Output file not found")
        return
    
    file_size = os.path.getsize(output_file_path)
    print(f"\nOutput file verification:")
    print(f"File size: {file_size} bytes")
    
    with open(output_file_path, 'rb') as f:
        packet_count = 0
        total_data_size = 0
        
        while True:
            # Read length
            length_bytes = f.read(4)
            if len(length_bytes) < 4:
                break
            
            packet_length = struct.unpack('<I', length_bytes)[0]
            
            # Read packet data
            packet_data = f.read(packet_length)
            if len(packet_data) < packet_length:
                print(f"Warning: Incomplete packet {packet_count + 1}")
                break
            
            packet_count += 1
            total_data_size += packet_length
            
            # Show info for first few packets
            if packet_count <= 3:
                preview = packet_data[:8].hex() if len(packet_data) >= 8 else packet_data.hex()
                print(f"Packet {packet_count}: {packet_length} bytes, starts with: {preview}")
        
        print(f"Total packets: {packet_count}")
        print(f"Total audio data: {total_data_size} bytes")
        print(f"Overhead: {file_size - total_data_size} bytes (length headers)")

def main():
    if len(sys.argv) != 3:
        print("Usage: python fixed_opus_extractor.py <input.ogg> <output.dat>")
        print("Example: python fixed_opus_extractor.py audio.ogg opus_packets.dat")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' not found.")
        sys.exit(1)
    
    print("Fixed Opus OGG to Custom Format Converter")
    print("=========================================")
    print(f"Input: {input_file}")
    print(f"Output: {output_file}")
    print()
    
    # Extract packets
    if extract_opus_packets(input_file, output_file):
        print(f"\nSuccess! Output saved to: {output_file}")
        
        # Verify the output
        verify_output_file(output_file)
    else:
        print("Extraction failed.")

if __name__ == "__main__":
    main()
