echo "INSTRUCTION CONSTRUCTED: MRET: " > isla_traces/machine_mret_simplified_trace.txt
isla/target/release/isla-footprint -A configs/riscv64-9454e6e8-IR-updated-init.ir -C isla/configs/riscv64.toml -i "mret" -s >> isla_traces/machine_mret_simplified_trace.txt
echo "INSTRUCTION CONSTRUCTED: SRET: " > isla_traces/machine_sret_simplified_trace.txt
isla/target/release/isla-footprint -A configs/riscv64-9454e6e8-IR-updated-init.ir -C isla/configs/riscv64.toml -i "sret" -s >> isla_traces/machine_sret_simplified_trace.txt
echo "INSTRUCTION CONSTRUCTED: URET: " > isla_traces/machine_uret_simplified_trace.txt
isla/target/release/isla-footprint -A configs/riscv64-9454e6e8-IR-updated-init.ir -C isla/configs/riscv64.toml -i "uret" -s >> isla_traces/machine_uret_simplified_trace.txt
echo "INSTRUCTION CONSTRUCTED: WFI: " > isla_traces/machine_wfi_simplified_trace.txt
isla/target/release/isla-footprint -A configs/riscv64-9454e6e8-IR-updated-init.ir -C isla/configs/riscv64.toml -i "wfi" -s >> isla_traces/machine_wfi_simplified_trace.txt
echo "INSTRUCTION CONSTRUCTED: SFENCE_VMA: " > isla_traces/machine_sfence_vma_simplified_trace.txt
isla/target/release/isla-footprint -A configs/riscv64-9454e6e8-IR-updated-init.ir -C isla/configs/riscv64.toml -i "sfence.vma" -s >> isla_traces/machine_sfence_vma_simplified_trace.txt
echo "INSTRUCTION CONSTRUCTED: MRET: " > isla_traces/supervisor_mret_simplified_trace.txt
isla/target/release/isla-footprint -A configs/riscv64-9454e6e8-IR-updated-init.ir -C isla/configs/riscv64.toml -i "mret" -s -R cur_privilege=Supervisor >> isla_traces/supervisor_mret_simplified_trace.txt
echo "INSTRUCTION CONSTRUCTED: SRET: " > isla_traces/supervisor_sret_simplified_trace.txt
isla/target/release/isla-footprint -A configs/riscv64-9454e6e8-IR-updated-init.ir -C isla/configs/riscv64.toml -i "sret" -s -R cur_privilege=Supervisor >> isla_traces/supervisor_sret_simplified_trace.txt
echo "INSTRUCTION CONSTRUCTED: URET: " > isla_traces/supervisor_uret_simplified_trace.txt
isla/target/release/isla-footprint -A configs/riscv64-9454e6e8-IR-updated-init.ir -C isla/configs/riscv64.toml -i "uret" -s -R cur_privilege=Supervisor >> isla_traces/supervisor_uret_simplified_trace.txt
echo "INSTRUCTION CONSTRUCTED: WFI: " > isla_traces/supervisor_wfi_simplified_trace.txt
isla/target/release/isla-footprint -A configs/riscv64-9454e6e8-IR-updated-init.ir -C isla/configs/riscv64.toml -i "wfi" -s -R cur_privilege=Supervisor >> isla_traces/supervisor_wfi_simplified_trace.txt
echo "INSTRUCTION CONSTRUCTED: SFENCE_VMA: " > isla_traces/supervisor_sfence_vma_simplified_trace.txt
isla/target/release/isla-footprint -A configs/riscv64-9454e6e8-IR-updated-init.ir -C isla/configs/riscv64.toml -i "sfence.vma" -s -R cur_privilege=Supervisor >> isla_traces/supervisor_sfence_vma_simplified_trace.txt
echo "INSTRUCTION CONSTRUCTED: MRET: " > isla_traces/user_mret_simplified_trace.txt
isla/target/release/isla-footprint -A configs/riscv64-9454e6e8-IR-updated-init.ir -C isla/configs/riscv64.toml -i "mret" -s -R cur_privilege=User >> isla_traces/user_mret_simplified_trace.txt
echo "INSTRUCTION CONSTRUCTED: SRET: " > isla_traces/user_sret_simplified_trace.txt
isla/target/release/isla-footprint -A configs/riscv64-9454e6e8-IR-updated-init.ir -C isla/configs/riscv64.toml -i "sret" -s -R cur_privilege=User >> isla_traces/user_sret_simplified_trace.txt
echo "INSTRUCTION CONSTRUCTED: URET: " > isla_traces/user_uret_simplified_trace.txt
isla/target/release/isla-footprint -A configs/riscv64-9454e6e8-IR-updated-init.ir -C isla/configs/riscv64.toml -i "uret" -s -R cur_privilege=User >> isla_traces/user_uret_simplified_trace.txt
echo "INSTRUCTION CONSTRUCTED: WFI: " > isla_traces/user_wfi_simplified_trace.txt
isla/target/release/isla-footprint -A configs/riscv64-9454e6e8-IR-updated-init.ir -C isla/configs/riscv64.toml -i "wfi" -s -R cur_privilege=User >> isla_traces/user_wfi_simplified_trace.txt
echo "INSTRUCTION CONSTRUCTED: SFENCE_VMA: " > isla_traces/user_sfence_vma_simplified_trace.txt
isla/target/release/isla-footprint -A configs/riscv64-9454e6e8-IR-updated-init.ir -C isla/configs/riscv64.toml -i "sfence.vma" -s -R cur_privilege=User >> isla_traces/user_sfence_vma_simplified_trace.txt
