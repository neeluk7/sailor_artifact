# -------------- # -------------- # -------------- # -------------- # -------------- # -------------- # -------------- # -------------- # -------------- #
# ---------------------------- Author: Neelu S. Kalani (neelu.kalani@ibm.com/neelukalani7@gmail.com) --------------------------------------------------- #
# -------------- # -------------- # -------------- # -------------- # -------------- # -------------- # -------------- # -------------- # -------------- #
# -------------- The results are put through a CSR-driven algorithm to generate the context switch info between two given privilege modes -------------- #
# -------------- # -------------- # -------------- # -------------- # -------------- # -------------- # -------------- # -------------- # -------------- #

import os;
import sys; 
#from lexer import *;
import csv; 

SUPPORTED_MODES = ["U", "S", "", "M"];

scanner_results_dir = "/scanner-results/";
analyzer_results_dir = "/analyzer-results/";
arch_scanner_results_dir = "";
arch_analyzer_results_dir = "";

arch_module = "";
arch_name = "";
results_dir = "";

SOURCE_MODE = "U";
TARGET_MODE = "U";

csr_list = ["fflags", "frm", "fcsr", "hpmcounter3", "hpmcounter4", "hpmcounter5", "hpmcounter6", "hpmcounter7", "hpmcounter8", "hpmcounter9", "hpmcounter10", "hpmcounter11", "hpmcounter12", "hpmcounter13", "hpmcounter14", "hpmcounter15", "hpmcounter16", "hpmcounter17", "hpmcounter18", "hpmcounter19", "hpmcounter20", "hpmcounter21", "hpmcounter22", "hpmcounter23", "hpmcounter24", "hpmcounter25", "hpmcounter26", "hpmcounter27", "hpmcounter28", "hpmcounter29", "hpmcounter30", "hpmcounter31", "mhpmevent3", "mhpmevent4", "mhpmevent5", "mhpmevent6", "mhpmevent7", "mhpmevent8", "mhpmevent9", "mhpmevent10", "mhpmevent11", "mhpmevent12", "mhpmevent13", "mhpmevent14", "mhpmevent15", "mhpmevent16", "mhpmevent17", "mhpmevent18", "mhpmevent19", "mhpmevent20", "mhpmevent21", "mhpmevent22", "mhpmevent23", "mhpmevent24", "mhpmevent25", "mhpmevent26", "mhpmevent27", "mhpmevent28", "mhpmevent29", "mhpmevent30", "mhpmevent31", "mhpmcounter3", "mhpmcounter4", "mhpmcounter5", "mhpmcounter6", "mhpmcounter7", "mhpmcounter8", "mhpmcounter9", "mhpmcounter10", "mhpmcounter11", "mhpmcounter12", "mhpmcounter13", "mhpmcounter14", "mhpmcounter15", "mhpmcounter16", "mhpmcounter17", "mhpmcounter18", "mhpmcounter19", "mhpmcounter20", "mhpmcounter21", "mhpmcounter22", "mhpmcounter23", "mhpmcounter24", "mhpmcounter25", "mhpmcounter26", "mhpmcounter27", "mhpmcounter28", "mhpmcounter29", "mhpmcounter30", "mhpmcounter31", "pmpcfg0", "pmpcfg1", "pmpcfg2", "pmpcfg3", "pmpcfg4", "pmpcfg5", "pmpcfg6", "pmpcfg7", "pmpcfg8", "pmpcfg9", "pmpcfg10", "pmpcfg11", "pmpcfg12", "pmpcfg13", "pmpcfg14", "pmpcfg15", "pmpaddr0", "pmpaddr1", "pmpaddr2", "pmpaddr3", "pmpaddr4", "pmpaddr5", "pmpaddr6", "pmpaddr7", "pmpaddr8", "pmpaddr9", "pmpaddr10", "pmpaddr11", "pmpaddr12", "pmpaddr13", "pmpaddr14", "pmpaddr15", "pmpaddr16", "pmpaddr17", "pmpaddr18", "pmpaddr19", "pmpaddr20", "pmpaddr21", "pmpaddr22", "pmpaddr23", "pmpaddr24", "pmpaddr25", "pmpaddr26", "pmpaddr27", "pmpaddr28", "pmpaddr29", "pmpaddr30", "pmpaddr31", "pmpaddr32", "pmpaddr33", "pmpaddr34", "pmpaddr35", "pmpaddr36", "pmpaddr37", "pmpaddr38", "pmpaddr39", "pmpaddr40", "pmpaddr41", "pmpaddr42", "pmpaddr43", "pmpaddr44", "pmpaddr45", "pmpaddr46", "pmpaddr47", "pmpaddr48", "pmpaddr49", "pmpaddr50", "pmpaddr51", "pmpaddr52", "pmpaddr53", "pmpaddr54", "pmpaddr55", "pmpaddr56", "pmpaddr57", "pmpaddr58", "pmpaddr59", "pmpaddr60", "pmpaddr61", "pmpaddr62", "pmpaddr63", "cycle", "time", "instret", "cycleh", "timeh", "instreth", "mcycle", "minstret", "mcycleh", "minstreth", "stimecmp", "stimecmph", "stvec", "sepc", "mtvec", "mepc", "misa", "mstatus", "menvcfg", "menvcfgh", "senvcfg", "mie", "mip", "medeleg", "medelegh", "mideleg", "mcause", "mtval", "mscratch", "scounteren", "mcounteren", "mcountinhibit", "mvendorid", "marchid", "mimpid", "mhartid", "mconfigptr", "sstatus", "sip", "sie", "sscratch", "scause", "stval", "tselect", "tdata1", "tdata2", "tdata3", "seed", "vstart", "vxsat", "vxrm", "vcsr", "vl", "vtype", "vlenb", "satp"];

# -------------------------------------------------------- Input from the scanner for the analyzer------------------------------------------------------ #

instruction_CSR_footprint = [{}, {}, {}, {}, {}];

instruction_execution_access = [{}, {}, {}, {}, {}];

CSR_read_access = [{}, {}, {}, {}, {}];

CSR_write_access = [{}, {}, {}, {}, {}];


# ----------------------------------------------- CSR-Driven Security Domain Switch Algorithm ---------------------------------------------------------- #

def switch_security_domain(source_mode, target_mode): 
   source_mode_id = SUPPORTED_MODES.index(source_mode);
   target_mode_id = SUPPORTED_MODES.index(target_mode);

   print("Source_mode_ID: "+str(source_mode_id));
   print("Target mode id: "+str(target_mode_id));

   csr_swap_list = [];  
   csr_do_nothing_list = [];

   # The following is only for RISC-V 
   # if source_mode_id == 2 or target_mode_id == 2: 
   #    print("Error: Attempt to switch on the reserved mode!");
   #    exit(0);

   for csr in csr_list: 
      csr_swap = False;
      source_affects = False;
      source_is_dependent = False;
      csr_name = csr;

      print("For CSR: "+csr_name);

      # We assume NExt extension to be disabled: so we will remove ustatus, uie, utvec, uscratch, uepc, ucause, utval, uip 
      #if csr_name in next_csr_list:
      #   continue;

      if CSR_write_access[source_mode_id][csr_name] == "Allowed" or CSR_write_access[source_mode_id][csr_name] == "Conditional": 
         # Source mode can directly write the CSR using CSR operation instructions. 
         print("source_affects directly = true");
         source_affects = True;
      if source_affects == False: 
         # Source mode cannot directly write the CSR using CSR operation instructions.
         # But need to check if execution in Source mode can indirectly affect/modify the content of the CSR. 
         # E.g. Source mode can execute floating point instructions which will lead to mstatus.FS bits being set to dirty. If it is not cleared, then Target mode can read that and infer that the floating point unit was used. 
         for instr in instruction_CSR_footprint[source_mode_id].keys():
            # TODO: Checking 'csr' itself in the list as there are some csr uses where the scanner doesn't detect if the use was a Read/Write. 
            # Until that is resolved in the scanner, we assume the use to be R+W.  
            if csr in instruction_CSR_footprint[source_mode_id][instr] or csr+" Write" in instruction_CSR_footprint[source_mode_id][instr] or csr+" R+W" in instruction_CSR_footprint[source_mode_id][instr]: 
            #if csr+" Write" in instruction_CSR_footprint[instr] or csr+" R+W" in instruction_CSR_footprint[instr]: 
               if "Allowed" in instruction_execution_access[source_mode_id][instr] or "Conditional" in instruction_execution_access[source_mode_id][instr]: 
                  # Source mode can indirectly modify the content of the CSR during execution
                  print("source affects idirectly true");
                  if csr_name == "misa": 
                     print("Instr: "+instr+" affects "+csr);
                  source_affects = True; 
                  break; 
      if source_affects == False: 
         # We want to check if execution in Source mode is dependent on the content of the CSR.
         # That would mean this CSR could contain some sentisitive information about the security domain we are switching from.
         for instr in instruction_CSR_footprint[source_mode_id].keys():
               # TODO: Checking 'csr' itself in the list as there are some csr uses where the scanner doesn't detect if the use was a Read/Write. 
               # Until that is resolved in the scanner, we assume the use to be R+W.  
               if csr in instruction_CSR_footprint[source_mode_id][instr] or csr+" Read" in instruction_CSR_footprint[source_mode_id][instr] or csr+" R+W" in instruction_CSR_footprint[source_mode_id][instr] or csr_name in instruction_CSR_footprint[source_mode_id][instr] or csr_name+" Read" in instruction_CSR_footprint[source_mode_id][instr] or csr_name+" R+W" in instruction_CSR_footprint[source_mode_id][instr]: 
                  if csr == "satp": 
                     print("Instr "+instr+" can read satp! Here is the instr_exec_acc for Source: "+instruction_execution_access[source_mode_id][instr]);
                  if "Allowed" in instruction_execution_access[source_mode_id][instr] or "Conditional" in instruction_execution_access[source_mode_id][instr]: 
                     print("source is dependent");
                     source_is_dependent = True;
                     break; 

      #if csr_name == "scause": 
         #print("For scause: source is dependent on "+csr+": "+str(source_is_dependent)+" and source affects "+csr+": "+str(source_affects));

      # If source affects the value of the CSR directly or indirectly OR if execution in source mode is dependent on the content of CSR
      if source_affects == True or source_is_dependent == True: 
         if CSR_read_access[target_mode_id][csr_name] == "Allowed" or CSR_read_access[target_mode_id][csr_name] == "Conditional": 
            print("Target directly reads");
            # Target mode can directly read the CSR using CSR operation instructions.
            # Direct side channel 
            # Must swap and restore! 
            csr_swap_list.append(csr);
            csr_swap = True; 
            #if csr_name == "scause":
               #print("Target can read scause");
         # Need to do this for all subset/superset type of CSRs! 
         # TODO: Should only be done for specific fields though!!! 
         #elif csr_name == "mstatus" and CSR_read_access[target_mode_id]["sstatus"]:
         #   csr_swap_list.append(csr);
         #   csr_swap = True; 
         #elif source_affects == True: 
         else: 
            # Target mode cannot directly read the CSR using CSR operation instructions. 
            # But since Source mode can still write this CSR, we want to check if Target mode is dependent on the content of the CSR. 
            # E.g. Source mode can switch off the Floating point extension, and if Target mode tries to use it, an exception will occur - which becomes a side-channel for the Source mode to observe. 
            for instr in instruction_CSR_footprint[source_mode_id].keys():
               # TODO: Checking 'csr' itself in the list as there are some csr uses where the scanner doesn't detect if the use was a Read/Write. 
               # Until that is resolved in the scanner, we assume the use to be R+W.  
               #if csr_name == "sedeleg" and instr == "LOAD": 
                  #print("Checking condition for sedeleg Read in LOAD's CSR footprint.");
                  #print(instruction_CSR_footprint[instr]);
               if csr in instruction_CSR_footprint[source_mode_id][instr] or csr+" Read" in instruction_CSR_footprint[source_mode_id][instr] or csr+" R+W" in instruction_CSR_footprint[source_mode_id][instr] or csr_name in instruction_CSR_footprint[source_mode_id][instr] or csr_name+" Read" in instruction_CSR_footprint[source_mode_id][instr] or csr_name+" R+W" in instruction_CSR_footprint[source_mode_id][instr]: 
                  #if csr_name == "sedeleg" and instr == "LOAD": 
                  #   print("Found sedeleg Read in LOAD's CSR footprint.");
                  if "Allowed" in instruction_execution_access[target_mode_id][instr] or "Conditional" in instruction_execution_access[target_mode_id][instr]: 
                    # if csr_name == "sedeleg" and instr == "LOAD": 
                    #    print("Found Target mode execution true for LOAD. (sedeleg Read)");
                    # if csr_name == "scause":
                    #    print("Target can be affected by scause");
                     print("Target indirectly reads");
                     csr_swap_list.append(csr);
                     csr_swap = True; 
                     break; 

      # If no need to swap then do nothing.
      # If source_affects_or_is_dependent == False, csr_swap will def be false, so we don't need an explicit check for that.
      if csr_swap == False:
         csr_do_nothing_list.append(csr);
         

   # A little post-processing 
   # For now we consider VS and XS to have the same action as FS (since we were not able to retrieve the ext_write_vcsr footprint in the analysis).
   # TODO: This should be fixed in Sailor Scanner. 
   if "mstatus[FS]" in csr_swap_list:
      if "mstatus[VS]" not in csr_swap_list: 
         csr_swap_list.append("mstatus[VS]");
         csr_do_nothing_list.remove("mstatus[VS]");
      if "mstatus[XS]" not in csr_swap_list: 
         csr_swap_list.append("mstatus[XS]");
         csr_do_nothing_list.remove("mstatus[XS]");

   if "sstatus[FS]" in csr_swap_list:
      if "sstatus[VS]" not in csr_swap_list: 
         csr_swap_list.append("sstatus[VS]");
         csr_do_nothing_list.remove("sstatus[VS]");
      if "sstatus[XS]" not in csr_swap_list: 
         csr_swap_list.append("sstatus[XS]");
         csr_do_nothing_list.remove("sstatus[XS]");

   # Next: We need to implement equivalence of mstatus and sstatus, sie and mie, sip and mip. 
   # TODO: Question: At what stage should this be? 

   """ 
   for csr in csr_swap_list: 
      csr_name = "";
      if "[" in csr: 
         csr_name = csr.split("[")[0];
      else: 
         csr_name = csr;
   
      if csr_name == "mstatus" or csr_name == "mie" or csr_name == "mip": 
         smode_csr = "s" + csr[1:];
         if smode_csr in csr_do_nothing_list:
            csr_do_nothing_list.remove(smode_csr);
            csr_swap_list.append(smode_csr);  
      elif csr_name == "sstatus" or csr_name == "sie" or csr_name == "sip":  
         mmode_csr = "m" + csr[1:];
         if mmode_csr in csr_do_nothing_list:
            csr_do_nothing_list.remove(mmode_csr);
            csr_swap_list.append(mmode_csr);  
   """
   
   print("For security domain switch from "+source_mode+"-mode to "+target_mode+"-mode:");
   print("\n***** Following CSRs are Security Sensitive: *****\n");
   #print(sorted(csr_swap_list));
   print(csr_swap_list);
   print("\n***** Following CSRs are NOT Security Sensitive: *****\n");
   #print(sorted(csr_do_nothing_list));
   print(csr_do_nothing_list);

   csv_output_file = open(arch_analyzer_results_dir+"switch-from-"+SOURCE_MODE+"-to-"+TARGET_MODE+".csv", "w", newline="");
   csv_writer = csv.writer(csv_output_file);

   csv_writer.writerow(["Security Sensitive","Not Security Sensitive"]);

   max_len = max(len(csr_swap_list),len(csr_do_nothing_list));

   for i in range(max_len): 
      row = [csr_swap_list[i] if i < len(csr_swap_list) else "", csr_do_nothing_list[i] if i < len(csr_do_nothing_list) else ""];
      csv_writer.writerow(row);

   csv_output_file.close();



results_dir = "CSVs";
arch_scanner_results_dir = results_dir + "/";
arch_analyzer_results_dir = results_dir + "/";


if SOURCE_MODE not in SUPPORTED_MODES: 
   print("We do not support analysis for this source mode! Following modes are supported: ");
   print(SUPPORTED_MODES);
   exit(0);

if TARGET_MODE not in SUPPORTED_MODES: 
   print("We do not support analysis for this target mode! Following modes are supported: ");
   print(SUPPORTED_MODES);
   exit(0);

# ----------------------------------------------------- Populating input from the CSVs ----------------------------------------------------------------- #    

csr_footprint_files_name = ["csr_footprint_per_instruction_user.csv", "csr_footprint_per_instruction_supervisor.csv", "", "csr_footprint_per_instruction_machine.csv"];
for index in range(4):
   if index == 2:
      continue;
   with open(arch_scanner_results_dir+csr_footprint_files_name[index], mode ='r') as infile:
      reader = csv.reader(infile)
      for row in reader:
         key = row[0];
         values = row[1:len(row)-1];
         while '' in values:
               values.remove('');
         while ' ' in values: 
               values.remove(' ');
         instruction_CSR_footprint[index][key] = values;

   print(instruction_CSR_footprint);

with open(arch_scanner_results_dir+'instruction_access_per_mode.csv', mode='r') as infile:
   reader = csv.reader(infile)
   for row in reader:
      key = row[0];
      if key == "Instruction":
         #or key == "WFI" or key == "VSETVLI":   # TODO: Check why there's no CSR footprint for VSETVLI  
         continue;

      if key not in instruction_CSR_footprint[0].keys():
            print("key not in CSR_footprint.keys(): "+key);
            exit(0);

      #print(key);        
 
      instruction_execution_access[0][key] = row[1];
      instruction_execution_access[1][key] = row[2];
      instruction_execution_access[3][key] = row[3];

with open(arch_scanner_results_dir+'csr_read_access.csv', mode='r') as infile: 
   reader = csv.reader(infile)
   for row in reader:
      key = row[0];
      if key == "CSR":
         continue;

      CSR_read_access[0][key] = row[1];
      CSR_read_access[1][key] = row[2];
      CSR_read_access[3][key] = row[3];

with open(arch_scanner_results_dir+'csr_write_access.csv', mode='r') as infile: 
   reader = csv.reader(infile)
   for row in reader:
      key = row[0];
      if key == "CSR":
         continue;

      CSR_write_access[0][key] = row[1];
      CSR_write_access[1][key] = row[2];
      CSR_write_access[3][key] = row[3];

print(instruction_execution_access);
print(CSR_read_access);
print(CSR_write_access);

switch_security_domain(SOURCE_MODE, TARGET_MODE);


