#!/usr/bin/env python3
"""
CSR Dependency Analyzer for Sailor/Isla Traces

This script analyzes trace files to find register dependencies:
- Does reading/writing register A always imply reading/writing register B?

Usage:
    python analyze_csr_dependencies.py <trace_file>
    
Example:
    python analyze_csr_dependencies.py ../experiment_runs/.../traces/rv64gc_all_traces_unpriv_simplified_Machine.txt
"""

import sys
import re
from collections import defaultdict
from typing import Set, Dict, List, Tuple

def extract_register_name(line: str) -> str:
    """
    Extract register name from a read-reg or write-reg line.
    Example: (read-reg |mstatus| nil ...) -> mstatus
    """
    match = re.search(r'\|([\w\[\]]+)\|', line)
    if match:
        return match.group(1)
    return None

def parse_trace_file(filename: str) -> List[Dict[str, Set[str]]]:
    """
    Parse the trace file and split it into individual traces.
    Each trace contains sets of registers that were read and written.
    
    Returns:
        List of dictionaries, each containing:
        {
            'reads': set of register names that were read,
            'writes': set of register names that were written
        }
    """
    traces = []
    current_trace = {'reads': set(), 'writes': set()}
    in_trace = False
    
    print(f"Reading trace file: {filename}")
    print("This may take a minute for large files...")
    
    with open(filename, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            
            # Track when we enter a new trace
            if line.startswith('(trace'):
                # Save previous trace if it has any data
                if current_trace['reads'] or current_trace['writes']:
                    traces.append(current_trace)
                # Start new trace
                current_trace = {'reads': set(), 'writes': set()}
                in_trace = True
                continue
            
            # Extract register reads
            if 'read-reg' in line:
                reg_name = extract_register_name(line)
                if reg_name:
                    current_trace['reads'].add(reg_name)
            
            # Extract register writes
            elif 'write-reg' in line:
                reg_name = extract_register_name(line)
                if reg_name:
                    current_trace['writes'].add(reg_name)
            
            # Progress indicator every 1 million lines
            if line_num % 1000000 == 0:
                print(f"  Processed {line_num:,} lines, found {len(traces)} traces so far...")
    
    # Don't forget the last trace
    if current_trace['reads'] or current_trace['writes']:
        traces.append(current_trace)
    
    print(f"✓ Finished parsing: found {len(traces)} traces")
    return traces

def analyze_dependencies(traces: List[Dict[str, Set[str]]]) -> Dict[str, Dict]:
    """
    Analyze register dependencies across all traces.
    
    For each register pair (A, B) and each operation type combination, check:
    - How often A appears (total)
    - When A appears, how often B also appears (together)
    - Calculate dependency percentage: together / total
    
    Returns dictionary with dependency statistics.
    """
    print("\nAnalyzing dependencies...")
    
    # We'll analyze 4 types of dependencies:
    # 1. READ-READ: A read implies B read
    # 2. READ-WRITE: A read implies B write  
    # 3. WRITE-READ: A write implies B read
    # 4. WRITE-WRITE: A write implies B write
    
    dependencies = {
        'READ-READ': defaultdict(lambda: {'together': 0}),
        'READ-WRITE': defaultdict(lambda: {'together': 0}),
        'WRITE-READ': defaultdict(lambda: {'together': 0}),
        'WRITE-WRITE': defaultdict(lambda: {'together': 0}),
    }
    
    # Count how many traces each register appears in (for 'total')
    read_counts = defaultdict(int)
    write_counts = defaultdict(int)
    
    # Get all unique registers
    all_registers = set()
    for trace in traces:
        all_registers.update(trace['reads'])
        all_registers.update(trace['writes'])
        # Count register occurrences
        for reg in trace['reads']:
            read_counts[reg] += 1
        for reg in trace['writes']:
            write_counts[reg] += 1
    
    print(f"  Found {len(all_registers)} unique registers")
    print(f"  Analyzing {len(traces)} traces...")
    
    # For each trace, check register co-occurrences
    for trace_num, trace in enumerate(traces, 1):
        if trace_num % 10000 == 0:
            print(f"    Processing trace {trace_num}/{len(traces)}...")
        
        # READ-READ dependencies: when reg_a is read, is reg_b also read?
        for reg_a in trace['reads']:
            for reg_b in trace['reads']:
                if reg_a != reg_b:
                    key = (reg_a, reg_b)
                    dependencies['READ-READ'][key]['together'] += 1
        
        # READ-WRITE dependencies: when reg_a is read, is reg_b written?
        for reg_a in trace['reads']:
            for reg_b in trace['writes']:
                if reg_a != reg_b:
                    key = (reg_a, reg_b)
                    dependencies['READ-WRITE'][key]['together'] += 1
        
        # WRITE-READ dependencies: when reg_a is written, is reg_b read?
        for reg_a in trace['writes']:
            for reg_b in trace['reads']:
                if reg_a != reg_b:
                    key = (reg_a, reg_b)
                    dependencies['WRITE-READ'][key]['together'] += 1
        
        # WRITE-WRITE dependencies: when reg_a is written, is reg_b also written?
        for reg_a in trace['writes']:
            for reg_b in trace['writes']:
                if reg_a != reg_b:
                    key = (reg_a, reg_b)
                    dependencies['WRITE-WRITE'][key]['together'] += 1
    
    # Add 'total' counts to each dependency
    for key in dependencies['READ-READ']:
        reg_a = key[0]
        dependencies['READ-READ'][key]['total'] = read_counts[reg_a]
    
    for key in dependencies['READ-WRITE']:
        reg_a = key[0]
        dependencies['READ-WRITE'][key]['total'] = read_counts[reg_a]
    
    for key in dependencies['WRITE-READ']:
        reg_a = key[0]
        dependencies['WRITE-READ'][key]['total'] = write_counts[reg_a]
    
    for key in dependencies['WRITE-WRITE']:
        reg_a = key[0]
        dependencies['WRITE-WRITE'][key]['total'] = write_counts[reg_a]
    
    print("✓ Dependency analysis complete")
    return dependencies

def report_dependencies(dependencies: Dict, min_correlation: float = 0.95, min_occurrences: int = 10):
    """
    Print a report of strong dependencies.
    
    Args:
        dependencies: Output from analyze_dependencies()
        min_correlation: Minimum correlation percentage to report (0.0-1.0)
        min_occurrences: Minimum number of occurrences to consider
    """
    print(f"\n{'='*80}")
    print(f"REGISTER DEPENDENCY REPORT")
    print(f"{'='*80}")
    print(f"Minimum correlation: {min_correlation*100:.0f}%")
    print(f"Minimum occurrences: {min_occurrences}")
    print()
    
    for dep_type in ['READ-READ', 'READ-WRITE', 'WRITE-READ', 'WRITE-WRITE']:
        print(f"\n{dep_type} Dependencies")
        print(f"{'-'*80}")
        
        found_any = False
        results = []
        
        for (reg_a, reg_b), stats in dependencies[dep_type].items():
            if stats['total'] >= min_occurrences:
                correlation = stats['together'] / stats['total']
                if correlation >= min_correlation:
                    results.append((correlation, reg_a, reg_b, stats['total'], stats['together']))
                    found_any = True
        
        # Sort by correlation (highest first)
        results.sort(reverse=True)
        
        if found_any:
            for correlation, reg_a, reg_b, total, together in results:
                print(f"  {reg_a:20s} => {reg_b:20s}  "
                      f"{correlation*100:5.1f}%  ({together}/{total} traces)")
        else:
            print(f"  No strong dependencies found")
    
    print(f"\n{'='*80}\n")

def main():
    if len(sys.argv) != 2:
        print("Usage: python analyze_csr_dependencies.py <trace_file>")
        print("\nExample:")
        print("  python analyze_csr_dependencies.py ../experiment_runs/.../traces/rv64gc_all_traces_unpriv_simplified_Machine.txt")
        sys.exit(1)
    
    trace_file = sys.argv[1]
    
    # Step 1: Parse traces
    traces = parse_trace_file(trace_file)
    
    # Step 2: Analyze dependencies
    dependencies = analyze_dependencies(traces)
    
    # Step 3: Report findings
    report_dependencies(dependencies, min_correlation=0.95, min_occurrences=10)
    
    print("Analysis complete!")

if __name__ == "__main__":
    main()
