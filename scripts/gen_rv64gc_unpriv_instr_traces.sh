#isla/target/release/isla-footprint -A ./configs/riscv64-9454e6e8-IR-updated-init.ir -C ./isla/configs/riscv64.toml -i "add a5, a3, a4" -s -n ./configs/rv64gc_all_opcodes_part_1.txt > ./isla_traces/rv64gc_all_traces_unpriv_simplified_Machine_part_1.txt || exit
#isla/target/release/isla-footprint -A ./configs/riscv64-9454e6e8-IR-updated-init.ir -C ./isla/configs/riscv64.toml -i "add a5, a3, a4" -s -n ./configs/rv64gc_all_opcodes_part_2.txt > ./isla_traces/rv64gc_all_traces_unpriv_simplified_Machine_part_2.txt || exit
#isla/target/release/isla-footprint -A ./configs/riscv64-9454e6e8-IR-updated-init.ir -C ./isla/configs/riscv64.toml -i "add a5, a3, a4" -s -n ./configs/rv64gc_all_opcodes_part_3.txt > ./isla_traces/rv64gc_all_traces_unpriv_simplified_Machine_part_3.txt || exit
#isla/target/release/isla-footprint -A ./configs/riscv64-9454e6e8-IR-updated-init.ir -C ./isla/configs/riscv64.toml -i "add a5, a3, a4" -s -n ./configs/rv64gc_all_opcodes_part_4.txt > ./isla_traces/rv64gc_all_traces_unpriv_simplified_Machine_part_4.txt || exit
#isla/target/release/isla-footprint -A ./configs/riscv64-9454e6e8-IR-updated-init.ir -C ./isla/configs/riscv64.toml -i "add a5, a3, a4" -s -n ./configs/rv64gc_all_opcodes_part_5.txt > ./isla_traces/rv64gc_all_traces_unpriv_simplified_Machine_part_5.txt || exit
isla/target/release/isla-footprint -A ./configs/riscv64-9454e6e8-IR-updated-init.ir -C ./isla/configs/riscv64.toml -i "add a5, a3, a4" -s -n ./configs/rv64gc_all_opcodes_part_6.txt > ./isla_traces/rv64gc_all_traces_unpriv_simplified_Machine_part_6.txt || exit


#isla/target/release/isla-footprint -A ./configs/riscv64-9454e6e8-IR-updated-init.ir -C ./isla/configs/riscv64.toml -i "add a5, a3, a4" -s -R cur_privilege=Supervisor -n ./configs/rv64gc_all_opcodes_part_1.txt > ./isla_traces/rv64gc_all_traces_unpriv_simplified_Supervisor_part_1.txt || exit
#isla/target/release/isla-footprint -A ./configs/riscv64-9454e6e8-IR-updated-init.ir -C ./isla/configs/riscv64.toml -i "add a5, a3, a4" -s -R cur_privilege=Supervisor -n ./configs/rv64gc_all_opcodes_part_2.txt > ./isla_traces/rv64gc_all_traces_unpriv_simplified_Supervisor_part_2.txt || exit
#isla/target/release/isla-footprint -A ./configs/riscv64-9454e6e8-IR-updated-init.ir -C ./isla/configs/riscv64.toml -i "add a5, a3, a4" -s -R cur_privilege=Supervisor -n ./configs/rv64gc_all_opcodes_part_3.txt > ./isla_traces/rv64gc_all_traces_unpriv_simplified_Supervisor_part_3.txt || exit
#isla/target/release/isla-footprint -A ./configs/riscv64-9454e6e8-IR-updated-init.ir -C ./isla/configs/riscv64.toml -i "add a5, a3, a4" -s -R cur_privilege=Supervisor -n ./configs/rv64gc_all_opcodes_part_4.txt > ./isla_traces/rv64gc_all_traces_unpriv_simplified_Supervisor_part_4.txt || exit
#isla/target/release/isla-footprint -A ./configs/riscv64-9454e6e8-IR-updated-init.ir -C ./isla/configs/riscv64.toml -i "add a5, a3, a4" -s -R cur_privilege=Supervisor -n ./configs/rv64gc_all_opcodes_part_5.txt > ./isla_traces/rv64gc_all_traces_unpriv_simplified_Supervisor_part_5.txt || exit
#isla/target/release/isla-footprint -A ./configs/riscv64-9454e6e8-IR-updated-init.ir -C ./isla/configs/riscv64.toml -i "add a5, a3, a4" -s -R cur_privilege=Supervisor -n ./configs/rv64gc_all_opcodes_part_6.txt > ./isla_traces/rv64gc_all_traces_unpriv_simplified_Supervisor_part_6.txt || exit



timestamp=$(date +%F_%T)
echo $timestamp > start_timestamp.txt

#isla/target/release/isla-footprint -A ./configs/riscv64-9454e6e8-IR-updated-init.ir -C ./isla/configs/riscv64.toml -i "add a5, a3, a4" -s -R cur_privilege=User -n ./configs/rv64gc_all_opcodes_part_1.txt > ./isla_traces/rv64gc_all_traces_unpriv_simplified_User_part_1.txt || exit
#isla/target/release/isla-footprint -A ./configs/riscv64-9454e6e8-IR-updated-init.ir -C ./isla/configs/riscv64.toml -i "add a5, a3, a4" -s -R cur_privilege=User -n ./configs/rv64gc_all_opcodes_part_2.txt > ./isla_traces/rv64gc_all_traces_unpriv_simplified_User_part_2.txt || exit
#isla/target/release/isla-footprint -A ./configs/riscv64-9454e6e8-IR-updated-init.ir -C ./isla/configs/riscv64.toml -i "add a5, a3, a4" -s -R cur_privilege=User -n ./configs/rv64gc_all_opcodes_part_3.txt > ./isla_traces/rv64gc_all_traces_unpriv_simplified_User_part_3.txt || exit
#isla/target/release/isla-footprint -A ./configs/riscv64-9454e6e8-IR-updated-init.ir -C ./isla/configs/riscv64.toml -i "add a5, a3, a4" -s -R cur_privilege=User -n ./configs/rv64gc_all_opcodes_part_4.txt > ./isla_traces/rv64gc_all_traces_unpriv_simplified_User_part_4.txt || exit
isla/target/release/isla-footprint -A ./configs/riscv64-9454e6e8-IR-updated-init.ir -C ./isla/configs/riscv64.toml -i "add a5, a3, a4" -s -R cur_privilege=User -n ./configs/rv64gc_all_opcodes_part_5.txt > ./isla_traces/rv64gc_all_traces_unpriv_simplified_User_part_5.txt || exit
isla/target/release/isla-footprint -A ./configs/riscv64-9454e6e8-IR-updated-init.ir -C ./isla/configs/riscv64.toml -i "add a5, a3, a4" -s -R cur_privilege=User -n ./configs/rv64gc_all_opcodes_part_6.txt > ./isla_traces/rv64gc_all_traces_unpriv_simplified_User_part_6.txt || exit

timestamp=$(date +%F_%T)
echo $timestamp > end_timestamp.txt 



