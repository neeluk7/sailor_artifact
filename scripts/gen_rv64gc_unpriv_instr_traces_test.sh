isla/target/release/isla-footprint -A ./configs/riscv64-9454e6e8-IR-updated-init.ir -C ./isla/configs/riscv64.toml -i "add a5, a3, a4" -s -n ./configs/rv64gc_test_opcodes.txt > ./isla_traces_test/rv64gc_all_traces_unpriv_simplified_Machine_test.txt || exit
isla/target/release/isla-footprint -A ./configs/riscv64-9454e6e8-IR-updated-init.ir -C ./isla/configs/riscv64.toml -i "add a5, a3, a4" -s -R cur_privilege=Supervisor -n ./configs/rv64gc_test_opcodes.txt > ./isla_traces_test/rv64gc_all_traces_unpriv_simplified_Supervisor_test.txt || exit
timestamp=$(date +%F_%T)
echo $timestamp > start_test_timestamp.txt
isla/target/release/isla-footprint -A ./configs/riscv64-9454e6e8-IR-updated-init.ir -C ./isla/configs/riscv64.toml -i "add a5, a3, a4" -s -R cur_privilege=User -n ./configs/rv64gc_test_opcodes.txt > ./isla_traces_test/rv64gc_all_traces_unpriv_simplified_User_test.txt || exit
timestamp=$(date +%F_%T)
echo $timestamp > end_test_timestamp.txt 



