import hashlib
import argparse
import sys
from termcolor import colored

def calculate_checksum(file_path, method):
    hash_func = None
    if method == 'md5':
        hash_func = hashlib.md5()
    elif method == 'sha1':
        hash_func = hashlib.sha1()
    elif method == 'sha256':
        hash_func = hashlib.sha256()
    else:
        print(colored(f"Unsupported checksum method: {method}", "red"))
        sys.exit(1)

    with open(file_path, 'rb') as f:
        while chunk := f.read(4096):
            hash_func.update(chunk)
    
    return hash_func.hexdigest()

def main():
    parser = argparse.ArgumentParser(description="Checksum verification script.")
    
    # Defining arguments with options
    parser.add_argument("-i", "--iso", required=True, type=str, help="Path to the ISO file")
    parser.add_argument("-m", "--method", required=True, choices=["md5", "sha1", "sha256"], help="Checksum method (md5, sha1, sha256)")
    parser.add_argument("-c", "--checksum", required=True, type=str, help="Checksum to compare against")
    
    args = parser.parse_args()

    # Calculate checksum of the given ISO file
    calculated_checksum = calculate_checksum(args.iso, args.method)

    print(f"Calculated {args.method} checksum: {calculated_checksum}")
    print(f"Provided checksum: {args.checksum}")

    # Compare checksums
    if calculated_checksum == args.checksum:
        print(colored("Checksums match!", "green"))
    else:
        print(colored("Checksums do not match!", "red"))

if __name__ == "__main__":
    main()