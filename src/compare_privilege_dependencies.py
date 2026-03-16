#!/usr/bin/env python3
"""
Compare CSR Dependencies Across Privilege Modes
"""

import sys
import re
from collections import defaultdict

def parse_dependency_report(filename):
    dependencies = {
        'READ-READ': {},
        'READ-WRITE': {},
        'WRITE-READ': {},
        'WRITE-WRITE': {},
    }
    
    current_type = None
    
    with open(filename, 'r') as f:
        for line in f:
            # Don't strip yet - we need to check the original line
            stripped = line.strip()
            
            # Detect dependency type sections
            if 'READ-READ Dependencies' in stripped:
                current_type = 'READ-READ'
            elif 'READ-WRITE Dependencies' in stripped:
                current_type = 'READ-WRITE'
            elif 'WRITE-READ Dependencies' in stripped:
                current_type = 'WRITE-READ'
            elif 'WRITE-WRITE Dependencies' in stripped:
                current_type = 'WRITE-WRITE'
            elif current_type and '=>' in stripped:
                # Match without leading whitespace since we stripped
                match = re.match(r'(\S+)\s+=>\s+(\S+)\s+(\d+\.\d+)%\s+\((\d+)/(\d+)\s+traces\)', stripped)
                if match:
                    reg_a, reg_b, corr_str, together_str, total_str = match.groups()
                    correlation = float(corr_str) / 100.0
                    together = int(together_str)
                    total = int(total_str)
                    
                    key = (reg_a, reg_b)
                    dependencies[current_type][key] = {
                        'correlation': correlation,
                        'together': together,
                        'total': total
                    }
    
    return dependencies

def compare_dependencies(machine_deps, supervisor_deps, user_deps, min_correlation=0.95):
    print("="*80)
    print("CSR DEPENDENCY COMPARISON ACROSS PRIVILEGE MODES")
    print("="*80)
    print()
    
    for dep_type in ['READ-READ', 'READ-WRITE', 'WRITE-READ', 'WRITE-WRITE']:
        print(f"\n{dep_type} Dependencies")
        print("-"*80)
        
        all_pairs = set()
        all_pairs.update(machine_deps[dep_type].keys())
        all_pairs.update(supervisor_deps[dep_type].keys())
        all_pairs.update(user_deps[dep_type].keys())
        
        machine_only = []
        supervisor_only = []
        user_only = []
        all_modes = []
        
        for pair in all_pairs:
            in_machine = pair in machine_deps[dep_type] and machine_deps[dep_type][pair]['correlation'] >= min_correlation
            in_supervisor = pair in supervisor_deps[dep_type] and supervisor_deps[dep_type][pair]['correlation'] >= min_correlation
            in_user = pair in user_deps[dep_type] and user_deps[dep_type][pair]['correlation'] >= min_correlation
            
            if in_machine and in_supervisor and in_user:
                all_modes.append(pair)
            elif in_machine:
                machine_only.append(pair)
            elif in_supervisor:
                supervisor_only.append(pair)
            elif in_user:
                user_only.append(pair)
        
        print(f"\nCommon to all 3 modes: {len(all_modes)} dependencies")
        if all_modes and len(all_modes) <= 20:
            for reg_a, reg_b in sorted(all_modes)[:20]:
                print(f"  {reg_a:20s} => {reg_b:20s}")
        elif all_modes:
            print(f"  (Showing first 20 of {len(all_modes)})")
            for reg_a, reg_b in sorted(all_modes)[:20]:
                print(f"  {reg_a:20s} => {reg_b:20s}")
        
        if machine_only:
            print(f"\nMachine mode ONLY: {len(machine_only)} dependencies")
            for reg_a, reg_b in sorted(machine_only)[:10]:
                corr = machine_deps[dep_type][(reg_a, reg_b)]['correlation'] * 100
                print(f"  {reg_a:20s} => {reg_b:20s}  {corr:.1f}%")
        
        if supervisor_only:
            print(f"\nSupervisor mode ONLY: {len(supervisor_only)} dependencies")
            for reg_a, reg_b in sorted(supervisor_only)[:10]:
                corr = supervisor_deps[dep_type][(reg_a, reg_b)]['correlation'] * 100
                print(f"  {reg_a:20s} => {reg_b:20s}  {corr:.1f}%")
        
        if user_only:
            print(f"\nUser mode ONLY: {len(user_only)} dependencies")
            for reg_a, reg_b in sorted(user_only)[:10]:
                corr = user_deps[dep_type][(reg_a, reg_b)]['correlation'] * 100
                print(f"  {reg_a:20s} => {reg_b:20s}  {corr:.1f}%")
    
    print("\n" + "="*80)
    print("\nSUMMARY")
    print("="*80)
    
    total_machine = sum(len(machine_deps[dt]) for dt in machine_deps)
    total_supervisor = sum(len(supervisor_deps[dt]) for dt in supervisor_deps)
    total_user = sum(len(user_deps[dt]) for dt in user_deps)
    
    print(f"Total dependencies (≥95% correlation):")
    print(f"  Machine mode:    {total_machine}")
    print(f"  Supervisor mode: {total_supervisor}")
    print(f"  User mode:       {total_user}")
    print()
    
    if total_machine == total_supervisor == total_user:
        print("✓ All three modes have the SAME number of strong dependencies")
        print("  This suggests privilege mode doesn't affect CSR dependency patterns")
    else:
        print("⚠ Different numbers of dependencies across modes")
        diff = max(total_machine, total_supervisor, total_user) - min(total_machine, total_supervisor, total_user)
        print(f"  Difference: {diff} dependencies")

def main():
    if len(sys.argv) != 4:
        print("Usage: python compare_privilege_dependencies.py <machine_file> <supervisor_file> <user_file>")
        sys.exit(1)
    
    machine_file, supervisor_file, user_file = sys.argv[1], sys.argv[2], sys.argv[3]
    
    print("Loading dependency reports...")
    machine_deps = parse_dependency_report(machine_file)
    supervisor_deps = parse_dependency_report(supervisor_file)
    user_deps = parse_dependency_report(user_file)
    print("✓ Loaded\n")
    
    compare_dependencies(machine_deps, supervisor_deps, user_deps)
    print("\nComparison complete!")

if __name__ == "__main__":
    main()
