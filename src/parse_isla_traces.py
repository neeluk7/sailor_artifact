import os; 
import sys; 
import csv;
import re;

def csv_to_dict(filename):
    """
    Converts a CSV file into a dictionary where:
        - Keys are from the first column.
        - Values are lists containing the remaining columns for each key.

    Args:
        filename (str): Path to the CSV file.

    Returns:
        dict: The converted dictionary.
    """

    result_dict = {}
    with open(filename, 'r') as file:
        reader = csv.reader(file)
        header = next(reader)  # Read the header row
        for row in reader:
            key = row[0]
            values = row[1:]  # Get all columns except the first
            result_dict[key] = values
    return result_dict

def csv_keys_to_list(filename): 
    """
    Extracts the first column of a CSV file into a list.
    
    Args:
    filename: Path to the CSV file.
    
    Returns:
    A list containing the values from the first column.
    """
    with open(filename, 'r') as file:
        reader = csv.reader(file)
        first_column = [row[0] for row in reader]
    return first_column

def find_list_diff(list_a, list_b):
  """
  Finds elements in list_a that are not present in list_b.

  Args:
    list_a: The first list.
    list_b: The second list.

  Returns:
    A list containing elements from list_a that are not in list_b.
  """
  return [x for x in list_a if x not in list_b];

isla_csr_footprint = [{}, {}, {}, {}]; 

instruction_access_per_mode = [{}, {}, {}, {}];

isla_results_files_paths = ["sailor_traces/rv64gc_all_traces_unpriv_simplified_Machine.txt", "sailor_traces/rv64gc_all_traces_unpriv_simplified_Supervisor.txt", "sailor_traces/rv64gc_all_traces_unpriv_simplified_User.txt","sailor_traces/rv64gc_remaining_traces_unpriv_simplified_Machine.txt","sailor_traces/rv64gc_remaining_traces_unpriv_simplified_Supervisor.txt", "sailor_traces/rv64gc_remaining_traces_unpriv_simplified_User.txt","sailor_traces/csr_access_traces_machine.txt","sailor_traces/csr_access_traces_supervisor.txt","sailor_traces/csr_access_traces_user.txt","sailor_traces/machine_mret_simplified_trace.txt", "sailor_traces/machine_sfence_vma_simplified_trace.txt", "sailor_traces/machine_sret_simplified_trace.txt", "sailor_traces/machine_uret_simplified_trace.txt", "sailor_traces/machine_wfi_simplified_trace.txt", "sailor_traces/supervisor_mret_simplified_trace.txt", "sailor_traces/supervisor_sfence_vma_simplified_trace.txt", "sailor_traces/supervisor_sret_simplified_trace.txt", "sailor_traces/supervisor_uret_simplified_trace.txt", "sailor_traces/supervisor_wfi_simplified_trace.txt", "sailor_traces/user_mret_simplified_trace.txt", "sailor_traces/user_sfence_vma_simplified_trace.txt", "sailor_traces/user_sret_simplified_trace.txt", "sailor_traces/user_uret_simplified_trace.txt", "sailor_traces/user_wfi_simplified_trace.txt"];

# Capture CSRs list
csr_list = ["fflags", "frm", "fcsr", "hpmcounter3", "hpmcounter4", "hpmcounter5", "hpmcounter6", "hpmcounter7", "hpmcounter8", "hpmcounter9", "hpmcounter10", "hpmcounter11", "hpmcounter12", "hpmcounter13", "hpmcounter14", "hpmcounter15", "hpmcounter16", "hpmcounter17", "hpmcounter18", "hpmcounter19", "hpmcounter20", "hpmcounter21", "hpmcounter22", "hpmcounter23", "hpmcounter24", "hpmcounter25", "hpmcounter26", "hpmcounter27", "hpmcounter28", "hpmcounter29", "hpmcounter30", "hpmcounter31", "mhpmevent3", "mhpmevent4", "mhpmevent5", "mhpmevent6", "mhpmevent7", "mhpmevent8", "mhpmevent9", "mhpmevent10", "mhpmevent11", "mhpmevent12", "mhpmevent13", "mhpmevent14", "mhpmevent15", "mhpmevent16", "mhpmevent17", "mhpmevent18", "mhpmevent19", "mhpmevent20", "mhpmevent21", "mhpmevent22", "mhpmevent23", "mhpmevent24", "mhpmevent25", "mhpmevent26", "mhpmevent27", "mhpmevent28", "mhpmevent29", "mhpmevent30", "mhpmevent31", "mhpmcounter3", "mhpmcounter4", "mhpmcounter5", "mhpmcounter6", "mhpmcounter7", "mhpmcounter8", "mhpmcounter9", "mhpmcounter10", "mhpmcounter11", "mhpmcounter12", "mhpmcounter13", "mhpmcounter14", "mhpmcounter15", "mhpmcounter16", "mhpmcounter17", "mhpmcounter18", "mhpmcounter19", "mhpmcounter20", "mhpmcounter21", "mhpmcounter22", "mhpmcounter23", "mhpmcounter24", "mhpmcounter25", "mhpmcounter26", "mhpmcounter27", "mhpmcounter28", "mhpmcounter29", "mhpmcounter30", "mhpmcounter31", "pmpcfg0", "pmpcfg1", "pmpcfg2", "pmpcfg3", "pmpcfg4", "pmpcfg5", "pmpcfg6", "pmpcfg7", "pmpcfg8", "pmpcfg9", "pmpcfg10", "pmpcfg11", "pmpcfg12", "pmpcfg13", "pmpcfg14", "pmpcfg15", "pmpaddr0", "pmpaddr1", "pmpaddr2", "pmpaddr3", "pmpaddr4", "pmpaddr5", "pmpaddr6", "pmpaddr7", "pmpaddr8", "pmpaddr9", "pmpaddr10", "pmpaddr11", "pmpaddr12", "pmpaddr13", "pmpaddr14", "pmpaddr15", "pmpaddr16", "pmpaddr17", "pmpaddr18", "pmpaddr19", "pmpaddr20", "pmpaddr21", "pmpaddr22", "pmpaddr23", "pmpaddr24", "pmpaddr25", "pmpaddr26", "pmpaddr27", "pmpaddr28", "pmpaddr29", "pmpaddr30", "pmpaddr31", "pmpaddr32", "pmpaddr33", "pmpaddr34", "pmpaddr35", "pmpaddr36", "pmpaddr37", "pmpaddr38", "pmpaddr39", "pmpaddr40", "pmpaddr41", "pmpaddr42", "pmpaddr43", "pmpaddr44", "pmpaddr45", "pmpaddr46", "pmpaddr47", "pmpaddr48", "pmpaddr49", "pmpaddr50", "pmpaddr51", "pmpaddr52", "pmpaddr53", "pmpaddr54", "pmpaddr55", "pmpaddr56", "pmpaddr57", "pmpaddr58", "pmpaddr59", "pmpaddr60", "pmpaddr61", "pmpaddr62", "pmpaddr63", "cycle", "time", "instret", "cycleh", "timeh", "instreth", "mcycle", "minstret", "mcycleh", "minstreth", "stimecmp", "stimecmph", "stvec", "sepc", "mtvec", "mepc", "misa", "mstatus", "menvcfg", "menvcfgh", "senvcfg", "mie", "mip", "medeleg", "medelegh", "mideleg", "mcause", "mtval", "mscratch", "scounteren", "mcounteren", "mcountinhibit", "mvendorid", "marchid", "mimpid", "mhartid", "mconfigptr", "sstatus", "sip", "sie", "sscratch", "scause", "stval", "tselect", "tdata1", "tdata2", "tdata3", "seed", "vstart", "vxsat", "vxrm", "vcsr", "vl", "vtype", "vlenb", "satp"];

# First compute isla_results...
curr_instruction_being_scanned = ""; 
instrs_found = 0;

for isla_results_file_path in isla_results_files_paths: 
    print(isla_results_file_path);
    isla_results_file = open(isla_results_file_path, "r");
    priv_mode_index_curr_traces = -1;    
    traces_for_this_instr = 0;
    illegal_instruction_traces = 0;

    if "Machine" in isla_results_file_path or "machine" in isla_results_file_path:    
        print("Machine mode!");
        priv_mode_index_curr_traces = 3;
    elif "Supervisor" in isla_results_file_path or "supervisor" in isla_results_file_path:    
        print("Supervisor mode!");
        priv_mode_index_curr_traces = 1;
    elif "User" in isla_results_file_path or "user" in isla_results_file_path:   
        print("User mode!"); 
        priv_mode_index_curr_traces = 0;
    
    if priv_mode_index_curr_traces == -1: 
        print("Couldn't determine priv mode from file name: "+isla_results_file_path);
        exit(0);

    isla_results_file_lines = isla_results_file.readlines(); 

    for cur_line in isla_results_file_lines: 
        if curr_instruction_being_scanned == "MRET" and "mcause" in cur_line: 
            print(cur_line);
        if "INSTRUCTION CONSTRUCTED:" in cur_line:  
            if traces_for_this_instr > 0 and curr_instruction_being_scanned != "": 
                if curr_instruction_being_scanned == "MRET": 
                    print("C For MRET: traces_for_this_instr: "+str(traces_for_this_instr)+" priv_mode: "+str(priv_mode_index_curr_traces));
                if curr_instruction_being_scanned == "FADD.D" and priv_mode_index_curr_traces == 1:
                    print("Supervisor mode for FADD.D");
                if curr_instruction_being_scanned == "FADD.D":
                    print("Any mode for FADD.D");
                if illegal_instruction_traces == 0:
                    instruction_access_per_mode[priv_mode_index_curr_traces][curr_instruction_being_scanned] = "Allowed";
                elif illegal_instruction_traces < traces_for_this_instr: 
                    instruction_access_per_mode[priv_mode_index_curr_traces][curr_instruction_being_scanned] = "Conditional";
                elif illegal_instruction_traces == traces_for_this_instr:
                    instruction_access_per_mode[priv_mode_index_curr_traces][curr_instruction_being_scanned] = "Not allowed";
                else: 
                    instruction_access_per_mode[priv_mode_index_curr_traces][curr_instruction_being_scanned] = "Undetermined";
            elif curr_instruction_being_scanned != "": 
                if curr_instruction_being_scanned == "FADD.D" and priv_mode_index_curr_traces == 1:
                    print("No traces Supervisor mode for FADD.D");
                if curr_instruction_being_scanned == "MRET": 
                    print("For MRET: traces_for_this_instr: "+str(traces_for_this_instr)+" priv_mode: "+str(priv_mode_index_curr_traces));
                instruction_access_per_mode[priv_mode_index_curr_traces][curr_instruction_being_scanned] = "No traces";

            traces_for_this_instr = 0;
            illegal_instruction_traces = 0;

            curr_instruction_being_scanned = cur_line.split(":")[1].replace(" ","");
            #print(curr_instruction_being_scanned);
            #if curr_instruction_being_scanned == "SLLI": 
            #    print("Found SLLI");
            if curr_instruction_being_scanned not in isla_csr_footprint[priv_mode_index_curr_traces].keys():
                isla_csr_footprint[priv_mode_index_curr_traces][curr_instruction_being_scanned] = [];
                instrs_found = instrs_found + 1;
        elif "(write-reg |mcause| nil (_ struct (|bits| #x0000000000000002)))" in cur_line: 
            if curr_instruction_being_scanned == "MRET": 
                print("Illegal For MRET: traces_for_this_instr: "+str(traces_for_this_instr)+" priv_mode: "+str(priv_mode_index_curr_traces));
            illegal_instruction_traces = illegal_instruction_traces + 1;
        elif "read-reg" in cur_line: 
            reg_name = cur_line.split("|")[1];
            # Only consider the Read if the value hasn't already been written ... Write + Read will not be dependent on a previously written value but the newly written value with the Write so it's not a true dependence.
            if reg_name in csr_list and reg_name+" Read" not in isla_csr_footprint[priv_mode_index_curr_traces][curr_instruction_being_scanned] and reg_name+" Write" not in isla_csr_footprint[priv_mode_index_curr_traces][curr_instruction_being_scanned]:        
                isla_csr_footprint[priv_mode_index_curr_traces][curr_instruction_being_scanned].append(reg_name+" Read");
        elif "write-reg" in cur_line: 
            reg_name = cur_line.split("|")[1];
            if reg_name in csr_list and reg_name+" Write" not in isla_csr_footprint[priv_mode_index_curr_traces][curr_instruction_being_scanned]:        
                isla_csr_footprint[priv_mode_index_curr_traces][curr_instruction_being_scanned].append(reg_name+" Write");
        elif "trace" in cur_line: 
            traces_for_this_instr = traces_for_this_instr + 1;

    if traces_for_this_instr > 0: 
        if curr_instruction_being_scanned == "MRET": 
            print("E For MRET: traces_for_this_instr: "+str(traces_for_this_instr)+" priv_mode: "+str(priv_mode_index_curr_traces));
        if illegal_instruction_traces == 0:
            instruction_access_per_mode[priv_mode_index_curr_traces][curr_instruction_being_scanned] = "Allowed";
        elif illegal_instruction_traces < traces_for_this_instr: 
            instruction_access_per_mode[priv_mode_index_curr_traces][curr_instruction_being_scanned] = "Conditional";
        elif illegal_instruction_traces == traces_for_this_instr:
            instruction_access_per_mode[priv_mode_index_curr_traces][curr_instruction_being_scanned] = "Not allowed";
        else: 
            instruction_access_per_mode[priv_mode_index_curr_traces][curr_instruction_being_scanned] = "Undetermined";
    else: 
        instruction_access_per_mode[priv_mode_index_curr_traces][curr_instruction_being_scanned] = "No traces";

    curr_instruction_being_scanned = "";

output_files_dir = "CSVs";
csr_footprint_files_name = ["csr_footprint_per_instruction_user.csv", "csr_footprint_per_instruction_supervisor.csv", "", "csr_footprint_per_instruction_machine.csv"];
instruction_access_per_mode_file_name = "instruction_access_per_mode.csv";

#isla_step_additions = ['mcountinhibit Read', 'mip R+W', 'mcause Write', 'mstatus R+W','medeleg Read','mideleg Read','mtval Write','mepc R+W', 'scause Write', 'sstatus R+W', 'stval Write', 'sepc R+W', 'mtvec Read', 'utval Write', 'uepc Write', 'ucause Read', 'stvec Read', 'utvec Read', 'sedeleg Read', 'minstret Write', 'instret Write', 'mcycle Write', 'cycle Write', 'mtime Write', 'time Write', 'mtimecmp Read', 'stimecmp Read', 'mhpmcounter3 Write', 'hpmcounter3 Write', 'mhpmcounter4 Write', 'hpmcounter4 Write', 'mhpmcounter5 Write', 'hpmcounter5 Write',  'mhpmcounter6 Write', 'hpmcounter6 Write',  'mhpmcounter7 Write', 'hpmcounter7 Write', 'mhpmcounter8 Write', 'hpmcounter8 Write',  'mhpmcounter9 Write', 'hpmcounter9 Write',  'mhpmcounter10 Write', 'hpmcounter10 Write', 'mhpmcounter11 Write', 'hpmcounter11 Write',  'mhpmcounter12 Write', 'hpmcounter12 Write',  'mhpmcounter13 Write', 'hpmcounter13 Write', 'mhpmcounter14 Write', 'hpmcounter14 Write',  'mhpmcounter15 Write', 'hpmcounter15 Write',  'mhpmcounter16 Write', 'hpmcounter16 Write', 'mhpmcounter17 Write', 'hpmcounter17 Write',  'mhpmcounter18 Write', 'hpmcounter18 Write',  'mhpmcounter19 Write', 'hpmcounter19 Write', 'mhpmcounter20 Write', 'hpmcounter20 Write', 'mhpmcounter21 Write', 'hpmcounter21 Write', 'mhpmcounter22 Write', 'hpmcounter22 Write', 'mhpmcounter23 Write', 'hpmcounter23 Write', 'mhpmcounter24 Write', 'hpmcounter24 Write', 'mhpmcounter25 Write', 'hpmcounter25 Write', 'mhpmcounter26 Write', 'hpmcounter26 Write', 'mhpmcounter27 Write', 'hpmcounter27 Write', 'mhpmcounter28 Write', 'hpmcounter28 Write', 'mhpmcounter29 Write', 'hpmcounter29 Write', 'mhpmcounter30 Write', 'hpmcounter30 Write', 'mhpmcounter31 Write', 'hpmcounter31 Write'];
isla_step_additions = [];

for index in range(4):
    if index == 2: 
        continue;
    for instr in isla_csr_footprint[index].keys():
        for elem in isla_step_additions:
            if elem not in isla_csr_footprint[index][instr]:
                isla_csr_footprint[index][instr].append(elem);

for index in range(4):
    if index == 2:
        continue;
    
    csr_footprint_file = open(output_files_dir+"/"+csr_footprint_files_name[index], 'w');
    csr_footprint_file_writer = csv.writer(csr_footprint_file);
    csr_footprint_file_writer.writerow(["Instruction", "CSR footprint"]);
    
    if index == 0:
        instruction_access_per_mode_file = open(output_files_dir+"/"+instruction_access_per_mode_file_name, 'w');
        instruction_access_per_mode_file_writer = csv.writer(instruction_access_per_mode_file);
        instruction_access_per_mode_file_writer.writerow(["Instruction", "User", "Supervisor", "Machine"]);

    for instr in isla_csr_footprint[index].keys(): 

        # Something's missing here... need to regen trace.
        if instr == "FADD.D" or instr == "FCVT.D.LU" or instr == "FMV.D.X": 
            continue;

        if instr not in instruction_access_per_mode[0].keys() or instr not in instruction_access_per_mode[1].keys() or instr not in instruction_access_per_mode[3].keys():
            continue;

        new_csr_footprint_row = [];
        new_csr_footprint_row.append(instr);
        for csr in isla_csr_footprint[index][instr]:
            new_csr_footprint_row.append(csr);
        csr_footprint_file_writer.writerow(new_csr_footprint_row);

        if index == 0:
            new_instr_access_row = [];
            new_instr_access_row.append(instr);
            new_instr_access_row.append(instruction_access_per_mode[0][instr]);
            new_instr_access_row.append(instruction_access_per_mode[1][instr]);
            new_instr_access_row.append(instruction_access_per_mode[3][instr]);

            instruction_access_per_mode_file_writer.writerow(new_instr_access_row);

    csr_footprint_file.close();
    if index == 0:
        instruction_access_per_mode_file.close();

