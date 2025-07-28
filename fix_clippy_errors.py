#!/usr/bin/env python3
"""
Script to fix clippy lint errors systematically
"""

import os
import re
import glob

def fix_lifetime_elision():
    """Fix elided lifetime parameters in types"""
    patterns = [
        (r'Result<JWE>', r'Result<JWE<\'_\'>'),
        (r'Result<JWS>', r'Result<JWS<\'_\'>'),  
        (r': ProtectedHeader =', r': ProtectedHeader<\'_\'> ='),
        (r'Vec::<ProtectedHeader>', r'Vec::<ProtectedHeader<\'_\'>'),
        (r': CompactHeader =', r': CompactHeader<\'_\'> ='),
        (r'Option<ParsedForward>', r'Option<ParsedForward<\'_\'>'),
    ]
    
    rust_files = glob.glob('src/**/*.rs', recursive=True)
    updated_files = []
    
    for file_path in rust_files:
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            original_content = content
            
            for old_pattern, new_pattern in patterns:
                content = re.sub(old_pattern, new_pattern, content)
            
            if content != original_content:
                with open(file_path, 'w') as f:
                    f.write(content)
                updated_files.append(file_path)
                print(f"Updated lifetime elisions in: {file_path}")
                
        except Exception as e:
            print(f"Error processing {file_path}: {e}")
    
    return updated_files

def fix_dead_code():
    """Fix dead code warnings by adding allow attributes"""
    # Add allow attributes for P384 dead code
    file_path = 'src/utils/crypto.rs'
    try:
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Add allow attribute before P384 variant
        content = re.sub(
            r'(    P256\(P256KeyPair\),\n)',
            r'\1    #[allow(dead_code)]\n',
            content
        )
        
        # Add allow attribute before as_p384 method  
        content = re.sub(
            r'(    fn as_p384\(&self\) -> Result<P384KeyPair> {)',
            r'    #[allow(dead_code)]\n    \1',
            content
        )
        
        with open(file_path, 'w') as f:
            f.write(content)
        print(f"Fixed dead code warnings in: {file_path}")
        
    except Exception as e:
        print(f"Error fixing dead code in {file_path}: {e}")

def fix_large_result_errors():
    """Fix large Result error warnings by adding allow attributes"""
    files_to_fix = [
        'src/jwe/encrypt.rs',
        'src/jwe/decrypt.rs',
        'src/message/pack_encrypted/mod.rs',
        'src/message/pack_signed.rs',
        'src/message/unpack.rs'
    ]
    
    for file_path in files_to_fix:
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Add allow attribute at the top after existing allows/warns
            if '#[allow(' not in content and '#[warn(' not in content:
                # Add after use statements
                content = re.sub(
                    r'(use [^;]+;\n\n)',
                    r'\1#[allow(clippy::result_large_err)]\n',
                    content,
                    count=1
                )
            else:
                # Find existing allow/warn and add ours
                content = re.sub(
                    r'(#\[(?:allow|warn)\([^\]]+\)\])',
                    r'\1\n#[allow(clippy::result_large_err)]',
                    content,
                    count=1
                )
            
            with open(file_path, 'w') as f:
                f.write(content)
            print(f"Fixed large result errors in: {file_path}")
            
        except Exception as e:
            print(f"Error fixing large result in {file_path}: {e}")

def main():
    print("Fixing clippy lint errors...")
    
    # Fix lifetime elision errors
    updated_files = fix_lifetime_elision()
    print(f"Fixed lifetime elisions in {len(updated_files)} files")
    
    # Fix dead code warnings  
    fix_dead_code()
    
    # Fix large result warnings
    fix_large_result_errors()
    
    print("Clippy fixes completed!")

if __name__ == "__main__":
    main()