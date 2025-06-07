import os;
import csv;

priv_modes = ["User", "Supervisor", "Machine"];
priv_mode_indices = [0, 1, 3]; 

csr_access_trap_or_success_undetermined = [];

csr_access_traces_output_files = ["sailor_traces/csr_access_traces_user.txt", "sailor_traces/csr_access_traces_supervisor.txt", "", "sailor_traces/csr_access_traces_machine.txt"];

def csr_access_csv_to_dicts(filename):
  """
  Converts a CSV file into three dictionaries where:
    - Keys are from the first column.
    - Values for each dictionary are from the corresponding subsequent column.

  Args:
    filename: Path to the CSV file.

  Returns:
    A tuple of three dictionaries.
  """
  with open(filename, 'r') as file:
    reader = csv.reader(file)
    dict1, dict2, dict3, dict4, dict5, dict6 = {}, {}, {}, {}, {}, {}
    next(reader)  # Skip header row (if any)
    for row in reader:
      key = row[0]
      if key == "CSR" or key == "fcsr[FRM]":
        continue; 
      dict1[key] = row[1]
      dict2[key] = row[2]
      dict3[key] = row[3]
      dict4[key] = row[4]
      dict5[key] = row[5]
      dict6[key] = row[6]
  return dict1, dict2, dict3, dict4, dict5, dict6


# Capture CSRs list
# csr_list = csv_keys_to_list(csr_access_file_path); 

csr_list = ["fflags", "frm", "fcsr", "hpmcounter3", "hpmcounter4", "hpmcounter5", "hpmcounter6", "hpmcounter7", "hpmcounter8", "hpmcounter9", "hpmcounter10", "hpmcounter11", "hpmcounter12", "hpmcounter13", "hpmcounter14", "hpmcounter15", "hpmcounter16", "hpmcounter17", "hpmcounter18", "hpmcounter19", "hpmcounter20", "hpmcounter21", "hpmcounter22", "hpmcounter23", "hpmcounter24", "hpmcounter25", "hpmcounter26", "hpmcounter27", "hpmcounter28", "hpmcounter29", "hpmcounter30", "hpmcounter31", "mhpmevent3", "mhpmevent4", "mhpmevent5", "mhpmevent6", "mhpmevent7", "mhpmevent8", "mhpmevent9", "mhpmevent10", "mhpmevent11", "mhpmevent12", "mhpmevent13", "mhpmevent14", "mhpmevent15", "mhpmevent16", "mhpmevent17", "mhpmevent18", "mhpmevent19", "mhpmevent20", "mhpmevent21", "mhpmevent22", "mhpmevent23", "mhpmevent24", "mhpmevent25", "mhpmevent26", "mhpmevent27", "mhpmevent28", "mhpmevent29", "mhpmevent30", "mhpmevent31", "mhpmcounter3", "mhpmcounter4", "mhpmcounter5", "mhpmcounter6", "mhpmcounter7", "mhpmcounter8", "mhpmcounter9", "mhpmcounter10", "mhpmcounter11", "mhpmcounter12", "mhpmcounter13", "mhpmcounter14", "mhpmcounter15", "mhpmcounter16", "mhpmcounter17", "mhpmcounter18", "mhpmcounter19", "mhpmcounter20", "mhpmcounter21", "mhpmcounter22", "mhpmcounter23", "mhpmcounter24", "mhpmcounter25", "mhpmcounter26", "mhpmcounter27", "mhpmcounter28", "mhpmcounter29", "mhpmcounter30", "mhpmcounter31", "pmpcfg0", "pmpcfg1", "pmpcfg2", "pmpcfg3", "pmpcfg4", "pmpcfg5", "pmpcfg6", "pmpcfg7", "pmpcfg8", "pmpcfg9", "pmpcfg10", "pmpcfg11", "pmpcfg12", "pmpcfg13", "pmpcfg14", "pmpcfg15", "pmpaddr0", "pmpaddr1", "pmpaddr2", "pmpaddr3", "pmpaddr4", "pmpaddr5", "pmpaddr6", "pmpaddr7", "pmpaddr8", "pmpaddr9", "pmpaddr10", "pmpaddr11", "pmpaddr12", "pmpaddr13", "pmpaddr14", "pmpaddr15", "pmpaddr16", "pmpaddr17", "pmpaddr18", "pmpaddr19", "pmpaddr20", "pmpaddr21", "pmpaddr22", "pmpaddr23", "pmpaddr24", "pmpaddr25", "pmpaddr26", "pmpaddr27", "pmpaddr28", "pmpaddr29", "pmpaddr30", "pmpaddr31", "pmpaddr32", "pmpaddr33", "pmpaddr34", "pmpaddr35", "pmpaddr36", "pmpaddr37", "pmpaddr38", "pmpaddr39", "pmpaddr40", "pmpaddr41", "pmpaddr42", "pmpaddr43", "pmpaddr44", "pmpaddr45", "pmpaddr46", "pmpaddr47", "pmpaddr48", "pmpaddr49", "pmpaddr50", "pmpaddr51", "pmpaddr52", "pmpaddr53", "pmpaddr54", "pmpaddr55", "pmpaddr56", "pmpaddr57", "pmpaddr58", "pmpaddr59", "pmpaddr60", "pmpaddr61", "pmpaddr62", "pmpaddr63", "cycle", "time", "instret", "cycleh", "timeh", "instreth", "mcycle", "minstret", "mcycleh", "minstreth", "stimecmp", "stimecmph", "stvec", "sepc", "mtvec", "mepc", "misa", "mstatus", "menvcfg", "menvcfgh", "senvcfg", "mie", "mip", "medeleg", "medelegh", "mideleg", "mcause", "mtval", "mscratch", "scounteren", "mcounteren", "mcountinhibit", "mvendorid", "marchid", "mimpid", "mhartid", "mconfigptr", "sstatus", "sip", "sie", "sscratch", "scause", "stval", "tselect", "tdata1", "tdata2", "tdata3", "seed", "vstart", "vxsat", "vxrm", "vcsr", "vl", "vtype", "vlenb", "satp"];
#csr_list = ["fflags", "fcsr", "instret"];

read_access = [{}, {}, {}, {}]; 
write_access = [{}, {}, {}, {}];
#read_access[0], write_access[0], read_access[1], write_access[1], read_access[3], write_access[3] = csr_access_csv_to_dicts(csr_access_file_path);

print("U-mode:");
print(read_access[0]);
print(write_access[0]);
print("S-mode:"); 
print(read_access[1]);
print(write_access[1]);
print("M-mode:");
print(read_access[3]);
print(write_access[3]);

# In the trace, if we find the following: 
# (cycle), (read-reg |cur_privilege| nil |<priv_mode>|), 
# (write-reg |mcause| nil (_ struct (|bits| #x0000000000000002))), 
# (define-enum |TrapVectorMode| 3 (|TV_Direct| |TV_Vector| |TV_Reserved|)) 
# then it's a trap, or else it's a regular execution! 
def check_for_trap_in_trace(trace_lines, csr, write, priv_mode): 
    trapped = False; 
    success = False;
    trapped_count = 0;
    success_count = 0; 
    priv_check_success = 0;
    encountered_cycle = 0;

    for line in trace_lines: 
        if encountered_cycle > 0: 
            if "(read-reg |cur_privilege| nil |"+priv_mode+"|)" in line:  
                priv_check_success = priv_check_success + 1; 
            elif "(write-reg |mcause| nil (_ struct (|bits| #x0000000000000002)))" in line: 
                trapped = True; 
            #elif "(define-enum |TrapVectorMode| 3 (|TV_Direct| |TV_Vector| |TV_Reserved|))" in line: 
            #    trapped = True; 
            # The following would be nice indeed to double check and be sure... but for now I will assume that if there is no trap, the access succeeds.
            # To fix this, we can extract the alias and subfield related information about CSRs from the Sail model and 
            #elif write == False and "(read-reg |"+csr in line: 
            #    success = True;
            #elif write == True and "(write-reg |"+csr in line: 
            #    success = True;
        if "(cycle)" in line: 
            if trapped == True: 
                trapped_count = trapped_count + 1; 
            elif encountered_cycle > 0: 
                success = True;
                success_count = success_count + 1; 
            if trapped == True and success == True: 
                print("Both trapped and success within a single trace for CSR: "+csr+" with encountered_cycle count: "+str(encountered_cycle));
            trapped = False;
            success = False; 
            encountered_cycle = encountered_cycle + 1; 
    
    if trapped == True: 
        trapped_count = trapped_count + 1; 
    elif encountered_cycle > (trapped_count + success_count): 
        success = True;
        success_count = success_count + 1; 
    
    # First verify cur_privilege. 

    if priv_check_success < encountered_cycle: 
        print("Priv check unsuccessful in trace for csr: "+csr+ " priv_check: "+str(priv_check_success) + " encountered cycles: "+str(encountered_cycle));
        #print(trace_lines);
        exit(0);

    # I don't remember why this exists ... but okay? 
    #if trapped_count > 0 and csr != "mtvec" and csr != "stvec" and csr != "utvec": 
    #    print("Invalid trap? for csr: "+csr);
        #print(trace_lines);
    #    exit(0);

    if (trapped_count + success_count) != encountered_cycle:
        if csr not in csr_access_trap_or_success_undetermined:
            csr_access_trap_or_success_undetermined.append(csr);
        #print("Who knows what's up! trapped + success != # of traces for CSR: "+csr+" trapped: "+ str(trapped_count) + " success: "+str(success_count) + " encountered cycles: "+str(encountered_cycle));
        #print(trace_lines);
        #exit(0);

    return (trapped_count, success_count); 

for priv_mode in priv_modes: 
    output_file = open(csr_access_traces_output_files[priv_mode_indices[priv_modes.index(priv_mode)]], 'w');
    # For each CSR, execute isla-footprint for the csrrs instruction, once with x10, x0..... i.e. csrr x10, <csr> - this covers checks for the CSR Read operation
    for csr in csr_list: 
        print("Checking read for CSR with priv mode: "+csr+" "+priv_mode);
        f = os.popen("target/release/isla-footprint -A ./isla-sail/IRs/riscv64-9454e6e8-IR-updated-init.ir -C configs/riscv64.toml -i 'csrr x10, "+csr+"' -s -R cur_privilege="+priv_mode, "r"); 
        output = f.readlines(); 

        for line in output: 
            output_file.write(line);

        (access_trapped, access_success) = check_for_trap_in_trace(output, csr, False, priv_mode);
        print("Access trapped: "+str(access_trapped)+" and success: "+str(access_success)+" for CSR with priv mode: "+csr+ " "+priv_mode+" ");
        if access_success == 0 and access_trapped > 0: 
            read_access[priv_mode_indices[priv_modes.index(priv_mode)]][csr] = "Not allowed";
        elif access_trapped == 0 and access_success > 0:
            read_access[priv_mode_indices[priv_modes.index(priv_mode)]][csr] = "Allowed";
        elif access_trapped > 0 and access_success > 0:
            read_access[priv_mode_indices[priv_modes.index(priv_mode)]][csr] = "Conditional";
        elif access_success == 0 and access_trapped == 0:
            read_access[priv_mode_indices[priv_modes.index(priv_mode)]][csr] = "Undetermined";

    # Again, for each CSR, execute isla-footprint for the CSRRW x0, csr, rs1 instruction --- to check for the CSR Write operation! 

    for csr in csr_list: 
        print("Checking write for CSR "+csr);
        f = os.popen("target/release/isla-footprint -A ./isla-sail/IRs/riscv64-9454e6e8-IR-updated-init.ir -C configs/riscv64.toml -i 'csrw "+csr+", x10' -s -R cur_privilege="+priv_mode, "r"); 
        output = f.readlines(); 

        for line in output: 
            output_file.write(line);

        (access_trapped, access_success) = check_for_trap_in_trace(output, csr, True, priv_mode);

        if access_success == 0 and access_trapped > 0: 
            write_access[priv_mode_indices[priv_modes.index(priv_mode)]][csr] = "Not allowed";
        elif access_trapped == 0 and access_success > 0:
            write_access[priv_mode_indices[priv_modes.index(priv_mode)]][csr] = "Allowed";
        elif access_trapped > 0 and access_success > 0:
            write_access[priv_mode_indices[priv_modes.index(priv_mode)]][csr] = "Conditional";
        elif access_success == 0 and access_trapped == 0:
            write_access[priv_mode_indices[priv_modes.index(priv_mode)]][csr] = "Undetermined";

print("Read access dict: ");
print(read_access);

print("Write access dict: ")
print(write_access);
    
print("Access undetermined");
print(csr_access_trap_or_success_undetermined);