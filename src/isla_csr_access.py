import os;
import csv;

priv_modes = ["User", "Supervisor", "Machine"];
priv_mode_indices = [0, 1, 3]; 

csr_access_trap_or_success_undetermined = [];

traces_dir = "isla_traces_dir/";

csr_access_traces_output_files = [traces_dir+"csr_access_traces_user.txt", traces_dir+"csr_access_traces_supervisor.txt", "", traces_dir+"csr_access_traces_machine.txt"];

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

#csr_list = ["fflags", "fcsr", "instret"];

csr_list_file = open("configs/csr_list.txt", "r");
csr_list_file_lines = csr_list_file.readlines();
csr_list_file.close();

csr_list = [];

for csr in csr_list_file_lines: 
    csr_list.append(csr.strip("\n"));

read_access = [{}, {}, {}, {}]; 
write_access = [{}, {}, {}, {}];
#read_access[0], write_access[0], read_access[1], write_access[1], read_access[3], write_access[3] = csr_access_csv_to_dicts(csr_access_file_path);

#print("U-mode:");
#print(read_access[0]);
#print(write_access[0]);
#print("S-mode:"); 
#print(read_access[1]);
#print(write_access[1]);
#print("M-mode:");
#print(read_access[3]);
#print(write_access[3]);

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
            #if trapped == True and success == True: 
            #    print("Both trapped and success within a single trace for CSR: "+csr+" with encountered_cycle count: "+str(encountered_cycle));
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
    output_file.write("INSTRUCTION CONSTRUCTED: CSRRW:\n");
    # For each CSR, execute isla-footprint for the csrrs instruction, once with x10, x0..... i.e. csrr x10, <csr> - this covers checks for the CSR Read operation
    for csr in csr_list: 
        #print("Checking read for CSR with priv mode: "+csr+" "+priv_mode);
        f = os.popen("isla/target/release/isla-footprint -A ./configs/riscv64-9454e6e8-IR-updated-init.ir -C isla/configs/riscv64.toml -i 'csrr x10, "+csr+"' -s -R cur_privilege="+priv_mode, "r"); 
        output = f.readlines(); 

        for line in output: 
            output_file.write(line);

        (access_trapped, access_success) = check_for_trap_in_trace(output, csr, False, priv_mode);
        #print("Access trapped: "+str(access_trapped)+" and success: "+str(access_success)+" for CSR with priv mode: "+csr+ " "+priv_mode+" ");
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
        #print("Checking write for CSR "+csr);
        f = os.popen("isla/target/release/isla-footprint -A ./configs/riscv64-9454e6e8-IR-updated-init.ir -C isla/configs/riscv64.toml -i 'csrw "+csr+", x10' -s -R cur_privilege="+priv_mode, "r"); 
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

#print("Read access dict: ");
#print(read_access);

#print("Write access dict: ")
#print(write_access);
    
#print("Access undetermined");
#print(csr_access_trap_or_success_undetermined);

output_files_dir = "CSVs";
csr_access_output_files = ["csr_read_access.csv", "csr_write_access.csv"]

def csr_access_dict_to_csv(dict_list, write, csv_writer):
    first_row = ["CSR", "User", "Supervisor", "Machine"];
    csv_writer.writerow(first_row);
    for csr in csr_list:
        new_row = [];
        new_row.append(csr);
        #if write == 1:
        #    new_row.append(csr+" Write");
        #else:
        #    new_row.append(csr+" Read");
        new_row.append(dict_list[0][csr]);
        new_row.append(dict_list[1][csr]);
        new_row.append(dict_list[3][csr]);
        csv_writer.writerow(new_row);

### CSR accesses per priv mode:

csv_file = open(output_files_dir+"/"+csr_access_output_files[0], 'w');
csv_file_writer = csv.writer(csv_file);
csr_access_dict_to_csv(read_access, 0, csv_file_writer);
csv_file.close();

csv_file = open(output_files_dir+"/"+csr_access_output_files[1], 'w');
csv_file_writer = csv.writer(csv_file);
csr_access_dict_to_csv(write_access, 1, csv_file_writer);
csv_file.close();
