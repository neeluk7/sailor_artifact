target/release/isla-footprint -A ./isla-sail/IRs/riscv64-9454e6e8-IR-updated-init.ir -C ./configs/riscv64.toml -i "add a5, a3, a4" -s -n rv64gc_all_opcodes.txt > sailor_traces/rv64gc_all_traces_unpriv_simplified_Machine.txt || exit
target/release/isla-footprint -A ./isla-sail/IRs/riscv64-9454e6e8-IR-updated-init.ir -C ./configs/riscv64.toml -i "add a5, a3, a4" -s -R cur_privilege=Supervisor -n rv64gc_all_opcodes.txt > sailor_traces/rv64gc_all_traces_unpriv_simplified_Supervisor.txt || exit
timestamp=$(date +%F_%T)
echo $timestamp > start_timestamp.txt
target/release/isla-footprint -A ./isla-sail/IRs/riscv64-9454e6e8-IR-updated-init.ir -C ./configs/riscv64.toml -i "add a5, a3, a4" -s -R cur_privilege=User -n rv64gc_all_opcodes.txt > sailor_traces/rv64gc_all_traces_unpriv_simplified_User.txt || exit
timestamp=$(date +%F_%T)
echo $timestamp > end_timestamp.txt 



