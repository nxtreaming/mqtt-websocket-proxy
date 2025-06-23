#!/usr/bin/env python3
"""
Create 40ms Opus frames using ffmpeg
"""

import subprocess
import sys
import os

def create_40ms_opus(input_file, output_file):
    """Use ffmpeg to create 40ms Opus frames"""
    
    # ffmpeg command to create 40ms Opus frames
    cmd = [
        'ffmpeg',
        '-i', input_file,           # Input file
        '-c:a', 'libopus',          # Use Opus codec
        '-frame_duration', '40',    # 40ms frame duration
        '-b:a', '64k',              # Bitrate (adjust as needed)
        '-vbr', 'off',              # Constant bitrate
        '-application', 'voip',     # Application type (voip, audio, lowdelay)
        '-y',                       # Overwrite output file
        output_file
    ]
    
    print(f"Creating 40ms Opus file: {output_file}")
    print(f"Command: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            print("Success! 40ms Opus file created.")
            return True
        else:
            print(f"Error: {result.stderr}")
            return False
    except Exception as e:
        print(f"Error running ffmpeg: {e}")
        return False

def main():
    if len(sys.argv) != 3:
        print("Usage: python create_40ms_opus.py <input_audio> <output.ogg>")
        print("Example: python create_40ms_opus.py input.wav output_40ms.ogg")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' not found.")
        sys.exit(1)
    
    if create_40ms_opus(input_file, output_file):
        print(f"\nNow you can extract 40ms frames using:")
        print(f"python fixed_opus_extractor.py {output_file} opus_40ms.dat")

if __name__ == "__main__":
    main()
