#!/usr/bin/env python3
"""
Convert strace.list to microhook.list with simplified format.

Input format:
    #ifdef TARGET_NR_accept
    { TARGET_NR_accept, "accept" , NULL, print_accept, NULL },
    #endif

Output format:
    #ifdef TARGET_NR_accept
    { TARGET_NR_accept, "accept"},
    #endif
"""

import re
import sys


def convert_strace_to_microhook(input_file, output_file):
    with open(input_file, 'r') as f:
        content = f.read()

    output_lines = []
    
    # Pattern to match #ifdef blocks
    # This handles multi-line struct entries
    ifdef_pattern = re.compile(
        r'(#ifdef\s+(TARGET_NR_\w+))\s*\n'  # #ifdef line
        r'\{\s*(TARGET_NR_\w+)\s*,\s*"([^"]+)"',  # Start of struct with name
        re.MULTILINE
    )

    # Process the file line by line to handle the structure
    lines = content.split('\n')
    i = 0
    while i < len(lines):
        line = lines[i]
        
        # Check for #ifdef TARGET_NR_
        ifdef_match = re.match(r'^#ifdef\s+(TARGET_NR_\w+)\s*$', line)
        if ifdef_match:
            target_nr = ifdef_match.group(1)
            output_lines.append(f'#ifdef {target_nr}')
            
            # Next line(s) should contain the struct entry
            i += 1
            if i < len(lines):
                # Collect lines until we hit #endif
                struct_lines = []
                while i < len(lines) and not lines[i].strip().startswith('#endif'):
                    struct_lines.append(lines[i])
                    i += 1
                
                # Parse the struct to extract the name
                struct_text = ' '.join(struct_lines)
                name_match = re.search(r'\{\s*TARGET_NR_\w+\s*,\s*"([^"]+)"', struct_text)
                if name_match:
                    name = name_match.group(1)
                    output_lines.append(f'{{ {target_nr}, "{name}"}},'  )
                
                # Add the #endif
                if i < len(lines) and lines[i].strip().startswith('#endif'):
                    output_lines.append('#endif')
                    i += 1
                continue
        
        i += 1

    with open(output_file, 'w') as f:
        f.write('\n'.join(output_lines))
        f.write('\n')


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input_strace.list> <output_microhook.list>",
              file=sys.stderr)
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    convert_strace_to_microhook(input_file, output_file)


if __name__ == '__main__':
    main()
