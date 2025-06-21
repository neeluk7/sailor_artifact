# This script is specific to U-mode to U-mode ... 
import csv; 
import os;

CSR_read_access = [{}, {}, {}, {}, {}];
CSR_write_access = [{}, {}, {}, {}, {}];
csr_sensitive_list = [];

arch_scanner_results_dir = "CSVs/";

tests_dir = "test-generator/tests/";

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

with open(arch_scanner_results_dir+'switch-from-U-to-U.csv', mode='r') as infile:
   reader = csv.reader(infile)
   for row in reader:
      csr = row[0];
      if csr == "Security Sensitive" or csr == "":
         continue;

      csr_sensitive_list.append(csr);

print(csr_sensitive_list);

csr_read_template_file_lines = open("test-generator/read_csr_app_template.c", "r").readlines();
csr_write_template_file_lines = open("test-generator/write_csr_app_template.c", "r").readlines();
csr_read_app_1_template_file_lines = open("test-generator/read_csr_app_1_template.c","r").readlines();
csr_read_app_2_template_file_lines = open("test-generator/read_csr_app_2_template.c","r").readlines();

compile_script_file = open(tests_dir+"build_tests.sh", "w");
#run_script_file = open(tests_dir+"run_tests.sh", "w");
programs_list_string = "";
csr_not_directly_accessible = [];

for csr in csr_sensitive_list:

   # CSR aliases 
   if csr == "minstret":
       csr = "instret";
   elif csr == "mcycle":
       csr = "cycle"; 
   elif csr == "mtime":
       csr = "time";

   csr_write = False; 
   csr_read = False;
   if CSR_write_access[0][csr] == "Conditional" or CSR_write_access[0][csr] == "Allowed":
      csr_write = True;
   
   if CSR_read_access[0][csr]  == "Conditional" or CSR_read_access[0][csr] == "Allowed":
      csr_read = True; 

   # Test for write and read ... (e.g. fcsr)
   if csr_write == True and csr_read == True: 
      read_test_file = open(tests_dir+csr+"_read_app.c", "w");
      write_test_file = open(tests_dir+csr+"_write_app.c", "w");

      for line in csr_read_template_file_lines:
         if "// INSERT CSR READ HERE. " in line: 
            read_test_file.write('asm volatile ("csrr %0, '+csr+'" : "=r" (value));\n');
         else: 
            read_test_file.write(line);

      for line in csr_write_template_file_lines:
         if "// INSERT CSR WRITE HERE. " in line: 
            write_test_file.write('asm volatile ("csrw '+csr+', %0" :: "r" (value));\n');
         else: 
            write_test_file.write(line);

      read_test_file.close();
      write_test_file.close();

      compile_script_file.write("gcc -o "+csr+"_read_app "+csr+"_read_app.c\n"); 
      compile_script_file.write("gcc -o "+csr+"_write_app "+csr+"_write_app.c\n"); 
      programs_list_string = programs_list_string + "./"+csr+"_write_app ./"+csr+"_read_app ";
   else: 
       csr_not_directly_accessible.append(csr);
   # Test for read and read ... (e.g. cycle) 
       if csr_write == False and csr_read == True: 
            read_once_test_file = open(tests_dir+csr+"_read_app_1.c", "w");
            read_twice_test_file = open(tests_dir+csr+"_read_app_2.c", "w");

            for line in csr_read_app_1_template_file_lines:
                if "// INSERT CSR READ HERE. " in line:
                    if csr == "instret" or csr == "cycle" or csr == "time":
                        read_once_test_file.write('asm volatile ("rd'+csr+' %0" : "=r" (value));\n');
                    else: 
                        read_once_test_file.write('asm volatile ("csrr %0, '+csr+'" : "=r" (value));\n');
                else:
                    read_once_test_file.write(line);
       
            for line in csr_read_app_2_template_file_lines:
                if "// INSERT CSR READ HERE. " in line:
                    if csr == "instret" or csr == "cycle" or csr == "time":
                        read_twice_test_file.write('asm volatile ("rd'+csr+' %0" : "=r" (value));\n');
                    else:
                        read_twice_test_file.write('asm volatile ("csrr %0, '+csr+'" : "=r" (value));\n');
                else:
                    read_twice_test_file.write(line);
            
            read_once_test_file.close();
            read_twice_test_file.close();

            compile_script_file.write("gcc -o "+csr+"_read_app_1 "+csr+"_read_app_1.c\n");
            compile_script_file.write("gcc -o "+csr+"_read_app_2 "+csr+"_read_app_2.c\n");
            programs_list_string = programs_list_string + "./"+csr+"_read_app_1 ./"+csr+"_read_app_2 ";

   # TODO: Put the commands in a script ... 
   
print("\n");
print(programs_list_string);

print("\n")
print(csr_not_directly_accessible);
