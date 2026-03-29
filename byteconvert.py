import os
import argparse

def file_to_bytes(input_file, output_file=None, chunk_size=4096):
    """
    Convert a file to .bytes format (hexadecimal representation)
    
    Args:
        input_file: Path to the input file
        output_file: Path to the output .bytes file (optional)
        chunk_size: Size of chunks to read at a time (in bytes)
    """
    if output_file is None:
        output_file = os.path.splitext(input_file)[0] + '.bytes'
    
    try:
        with open(input_file, 'rb') as f_in, open(output_file, 'w') as f_out:
            while True:
                chunk = f_in.read(chunk_size)
                if not chunk:
                    break
                
                # Convert each byte to two-digit hexadecimal and join with spaces
                hex_bytes = ' '.join(f'{byte:02X}' for byte in chunk)
                f_out.write(hex_bytes + ' ')
                
        print(f"Successfully converted {input_file} to {output_file}")
        return True
    
    except Exception as e:
        print(f"Error processing {input_file}: {str(e)}")
        return False

def batch_convert(input_path, output_dir=None):
    """
    Convert all files in a directory (or a single file) to .bytes format
    
    Args:
        input_path: Path to file or directory
        output_dir: Output directory (optional)
    """
    if os.path.isfile(input_path):
        # Single file conversion
        if output_dir:
            output_file = os.path.join(output_dir, 
                                      os.path.splitext(os.path.basename(input_path))[0] + '.bytes')
        else:
            output_file = None
        file_to_bytes(input_path, output_file)
    elif os.path.isdir(input_path):
        # Batch conversion
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        for root, _, files in os.walk(input_path):
            for file in files:
                input_file = os.path.join(root, file)
                if output_dir:
                    rel_path = os.path.relpath(root, input_path)
                    out_dir = os.path.join(output_dir, rel_path)
                    if not os.path.exists(out_dir):
                        os.makedirs(out_dir)
                    output_file = os.path.join(out_dir, 
                                             os.path.splitext(file)[0] + '.bytes')
                else:
                    output_file = None
                file_to_bytes(input_file, output_file)
    else:
        print(f"Error: {input_path} is not a valid file or directory")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Convert files to .bytes format for malware analysis')
    parser.add_argument('input', help='Input file or directory path')
    parser.add_argument('-o', '--output', help='Output directory (optional)')
    args = parser.parse_args()
    
    batch_convert(args.input, args.output)
