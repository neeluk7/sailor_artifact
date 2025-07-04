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

isla_results_files_path = "./isla_traces_dir/";
isla_results_files = ["rv64gc_all_traces_unpriv_simplified_Machine.txt", "rv64gc_all_traces_unpriv_simplified_Supervisor.txt", "rv64gc_all_traces_unpriv_simplified_User.txt","rv64gc_remaining_traces_unpriv_simplified_Machine.txt","rv64gc_remaining_traces_unpriv_simplified_Supervisor.txt", "rv64gc_remaining_traces_unpriv_simplified_User.txt","csr_access_traces_machine.txt","csr_access_traces_supervisor.txt","csr_access_traces_user.txt","machine_mret_simplified_trace.txt", "machine_sfence_vma_simplified_trace.txt", "machine_sret_simplified_trace.txt", "machine_uret_simplified_trace.txt", "machine_wfi_simplified_trace.txt", "supervisor_mret_simplified_trace.txt", "supervisor_sfence_vma_simplified_trace.txt", "supervisor_sret_simplified_trace.txt", "supervisor_uret_simplified_trace.txt", "supervisor_wfi_simplified_trace.txt", "user_mret_simplified_trace.txt", "user_sfence_vma_simplified_trace.txt", "user_sret_simplified_trace.txt", "user_uret_simplified_trace.txt", "user_wfi_simplified_trace.txt"];

# Capture CSRs list
csr_list_file = open("configs/csr_list.txt", "r");
csr_list_file_lines = csr_list_file.readlines();
csr_list_file.close();

csr_list = [];

for csr in csr_list_file_lines: 
    csr_list.append(csr.strip("\n"));

# First compute isla_results...
curr_instruction_being_scanned = ""; 
instrs_found = 0;

for isla_results_file_name in isla_results_files: 
    #print(isla_results_file_name);
    isla_results_file = open(isla_results_files_path+isla_results_file_name, "r");
    priv_mode_index_curr_traces = -1;    
    traces_for_this_instr = 0;
    illegal_instruction_traces = 0;

    if "Machine" in isla_results_file_name or "machine" in isla_results_file_name:    
        #print("Machine mode!");
        priv_mode_index_curr_traces = 3;
    elif "Supervisor" in isla_results_file_name or "supervisor" in isla_results_file_name:    
        #print("Supervisor mode!");
        priv_mode_index_curr_traces = 1;
    elif "User" in isla_results_file_name or "user" in isla_results_file_name:   
        #print("User mode!"); 
        priv_mode_index_curr_traces = 0;
    
    if priv_mode_index_curr_traces == -1: 
        print("Couldn't determine priv mode from file name: "+isla_results_file_name);
        exit(0);

    isla_results_file_lines = isla_results_file.readlines(); 

    for cur_line in isla_results_file_lines: 
        #if curr_instruction_being_scanned == "MRET" and "mcause" in cur_line: 
            #print(cur_line);
        if "INSTRUCTION CONSTRUCTED:" in cur_line:  
            if traces_for_this_instr > 0 and curr_instruction_being_scanned != "": 
                #if curr_instruction_being_scanned == "MRET": 
                #    print("C For MRET: traces_for_this_instr: "+str(traces_for_this_instr)+" priv_mode: "+str(priv_mode_index_curr_traces));
                #if curr_instruction_being_scanned == "FADD.D" and priv_mode_index_curr_traces == 1:
                #    print("Supervisor mode for FADD.D");
                #if curr_instruction_being_scanned == "FADD.D":
                #    print("Any mode for FADD.D");
                if illegal_instruction_traces == 0:
                    instruction_access_per_mode[priv_mode_index_curr_traces][curr_instruction_being_scanned] = "Allowed";
                elif illegal_instruction_traces < traces_for_this_instr: 
                    instruction_access_per_mode[priv_mode_index_curr_traces][curr_instruction_being_scanned] = "Conditional";
                elif illegal_instruction_traces == traces_for_this_instr:
                    instruction_access_per_mode[priv_mode_index_curr_traces][curr_instruction_being_scanned] = "Not allowed";
                else: 
                    instruction_access_per_mode[priv_mode_index_curr_traces][curr_instruction_being_scanned] = "Undetermined";
            elif curr_instruction_being_scanned != "": 
                #if curr_instruction_being_scanned == "FADD.D" and priv_mode_index_curr_traces == 1:
                #    print("No traces Supervisor mode for FADD.D");
                #if curr_instruction_being_scanned == "MRET": 
                #    print("For MRET: traces_for_this_instr: "+str(traces_for_this_instr)+" priv_mode: "+str(priv_mode_index_curr_traces));
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
            #if curr_instruction_being_scanned == "MRET": 
            #    print("Illegal For MRET: traces_for_this_instr: "+str(traces_for_this_instr)+" priv_mode: "+str(priv_mode_index_curr_traces));
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
        #if curr_instruction_being_scanned == "MRET": 
        #    print("E For MRET: traces_for_this_instr: "+str(traces_for_this_instr)+" priv_mode: "+str(priv_mode_index_curr_traces));
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

