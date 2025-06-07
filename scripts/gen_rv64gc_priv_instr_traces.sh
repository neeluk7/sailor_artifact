echo "INSTRUCTION CONSTRUCTED: MRET: " > sailor_traces/machine_mret_simplified_trace.txt
target/release/isla-footprint -A ./isla-sail/IRs/riscv64-9454e6e8-IR-updated-init.ir -C configs/riscv64.toml -i "mret" -s >> sailor_traces/machine_mret_simplified_trace.txt
echo "INSTRUCTION CONSTRUCTED: SRET: " > sailor_traces/machine_sret_simplified_trace.txt
target/release/isla-footprint -A ./isla-sail/IRs/riscv64-9454e6e8-IR-updated-init.ir -C configs/riscv64.toml -i "sret" -s >> sailor_traces/machine_sret_simplified_trace.txt
echo "INSTRUCTION CONSTRUCTED: URET: " > sailor_traces/machine_uret_simplified_trace.txt
target/release/isla-footprint -A ./isla-sail/IRs/riscv64-9454e6e8-IR-updated-init.ir -C configs/riscv64.toml -i "uret" -s >> sailor_traces/machine_uret_simplified_trace.txt
echo "INSTRUCTION CONSTRUCTED: WFI: " > sailor_traces/machine_wfi_simplified_trace.txt
target/release/isla-footprint -A ./isla-sail/IRs/riscv64-9454e6e8-IR-updated-init.ir -C configs/riscv64.toml -i "wfi" -s >> sailor_traces/machine_wfi_simplified_trace.txt
echo "INSTRUCTION CONSTRUCTED: SFENCE_VMA: " > sailor_traces/machine_sfence_vma_simplified_trace.txt
target/release/isla-footprint -A ./isla-sail/IRs/riscv64-9454e6e8-IR-updated-init.ir -C configs/riscv64.toml -i "sfence.vma" -s >> sailor_traces/machine_sfence_vma_simplified_trace.txt
echo "INSTRUCTION CONSTRUCTED: MRET: " > sailor_traces/supervisor_mret_simplified_trace.txt
target/release/isla-footprint -A ./isla-sail/IRs/riscv64-9454e6e8-IR-updated-init.ir -C configs/riscv64.toml -i "mret" -s -R cur_privilege=Supervisor >> sailor_traces/supervisor_mret_simplified_trace.txt
echo "INSTRUCTION CONSTRUCTED: SRET: " > sailor_traces/supervisor_sret_simplified_trace.txt
target/release/isla-footprint -A ./isla-sail/IRs/riscv64-9454e6e8-IR-updated-init.ir -C configs/riscv64.toml -i "sret" -s -R cur_privilege=Supervisor >> sailor_traces/supervisor_sret_simplified_trace.txt
echo "INSTRUCTION CONSTRUCTED: URET: " > sailor_traces/supervisor_uret_simplified_trace.txt
target/release/isla-footprint -A ./isla-sail/IRs/riscv64-9454e6e8-IR-updated-init.ir -C configs/riscv64.toml -i "uret" -s -R cur_privilege=Supervisor >> sailor_traces/supervisor_uret_simplified_trace.txt
echo "INSTRUCTION CONSTRUCTED: WFI: " > sailor_traces/supervisor_wfi_simplified_trace.txt
target/release/isla-footprint -A ./isla-sail/IRs/riscv64-9454e6e8-IR-updated-init.ir -C configs/riscv64.toml -i "wfi" -s -R cur_privilege=Supervisor >> sailor_traces/supervisor_wfi_simplified_trace.txt
echo "INSTRUCTION CONSTRUCTED: SFENCE_VMA: " > sailor_traces/supervisor_sfence_vma_simplified_trace.txt
target/release/isla-footprint -A ./isla-sail/IRs/riscv64-9454e6e8-IR-updated-init.ir -C configs/riscv64.toml -i "sfence.vma" -s -R cur_privilege=Supervisor >> sailor_traces/supervisor_sfence_vma_simplified_trace.txt
echo "INSTRUCTION CONSTRUCTED: MRET: " > sailor_traces/user_mret_simplified_trace.txt
target/release/isla-footprint -A ./isla-sail/IRs/riscv64-9454e6e8-IR-updated-init.ir -C configs/riscv64.toml -i "mret" -s -R cur_privilege=User >> sailor_traces/user_mret_simplified_trace.txt
echo "INSTRUCTION CONSTRUCTED: SRET: " > sailor_traces/user_sret_simplified_trace.txt
target/release/isla-footprint -A ./isla-sail/IRs/riscv64-9454e6e8-IR-updated-init.ir -C configs/riscv64.toml -i "sret" -s -R cur_privilege=User >> sailor_traces/user_sret_simplified_trace.txt
echo "INSTRUCTION CONSTRUCTED: URET: " > sailor_traces/user_uret_simplified_trace.txt
target/release/isla-footprint -A ./isla-sail/IRs/riscv64-9454e6e8-IR-updated-init.ir -C configs/riscv64.toml -i "uret" -s -R cur_privilege=User >> sailor_traces/user_uret_simplified_trace.txt
echo "INSTRUCTION CONSTRUCTED: WFI: " > sailor_traces/user_wfi_simplified_trace.txt
target/release/isla-footprint -A ./isla-sail/IRs/riscv64-9454e6e8-IR-updated-init.ir -C configs/riscv64.toml -i "wfi" -s -R cur_privilege=User >> sailor_traces/user_wfi_simplified_trace.txt
echo "INSTRUCTION CONSTRUCTED: SFENCE_VMA: " > sailor_traces/user_sfence_vma_simplified_trace.txt
target/release/isla-footprint -A ./isla-sail/IRs/riscv64-9454e6e8-IR-updated-init.ir -C configs/riscv64.toml -i "sfence.vma" -s -R cur_privilege=User >> sailor_traces/user_sfence_vma_simplified_trace.txt
