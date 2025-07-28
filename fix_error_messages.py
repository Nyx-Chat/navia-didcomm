#!/usr/bin/env python3
"""
Script to systematically update error message assertions in tests 
to match the enhanced error system.
"""

import os
import re
import glob

def get_error_mappings():
    """Define the mapping from old error messages to new ones."""
    return [
        # Main error kind mappings
        (r'"Malformed:', r'"Message malformed or invalid:'),
        (r'"Invalid state:', r'"Invalid system state:'),
        (r'"DID not resolved:', r'"DID not resolved:'),  # This one might not change
        (r'"Secret not found:', r'"Secret not found:'),  # This one might not change
        (r'"No compatible crypto:', r'"No compatible cryptographic algorithms found:'),
        (r'"Unsupported crypto or method:', r'"Unsupported cryptographic algorithm or method:'),
        (r'"IO error:', r'"IO operation failed:'),
        (r'"Illegal argument:', r'"Illegal argument provided:'),
        
        # Handle nested error messages that appear in chains
        (r'Malformed: Unable', r'Message malformed or invalid: Unable'),
        (r'Invalid state: Unable', r'Invalid system state: Unable'),
        (r'Invalid state: Wrong', r'Invalid system state: Wrong'),
        (r'Invalid state: Recipient', r'Invalid system state: Recipient'),
        (r'Invalid state: No sender', r'Invalid system state: No sender'),
    ]

def fix_file(file_path):
    """Fix error message assertions in a single file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        mappings = get_error_mappings()
        
        for old_pattern, new_pattern in mappings:
            content = re.sub(old_pattern, new_pattern, content)
        
        if content != original_content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"Updated: {file_path}")
            return True
        return False
        
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return False

def main():
    """Main function to process all Rust test files."""
    # Find all Rust files in src/ directory (where unit tests are)
    rust_files = []
    for root, dirs, files in os.walk('src'):
        for file in files:
            if file.endswith('.rs'):
                rust_files.append(os.path.join(root, file))
    
    print(f"Found {len(rust_files)} Rust files to process...")
    
    updated_count = 0
    for file_path in rust_files:
        if fix_file(file_path):
            updated_count += 1
    
    print(f"\nCompleted! Updated {updated_count} files.")
    print("\nNow run 'cargo test --lib' to see if more fixes are needed.")

if __name__ == "__main__":
    main()