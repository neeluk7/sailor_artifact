.PHONY: setup-dependencies setup-sail-riscv setup-isla gen-isla-traces-full isla-traces-test isla-parse-test run-sailor clean 

setup-dependencies: 
	sudo apt install gcc-riscv64-linux-gnu
	sudo apt-get install opam
	opam init
	eval $(opam config env)
	sudo apt-get install curl
	curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh 
	rustup default 1.86.0
	opam install z3=4.8.13
	git submodule update --init --recursive

setup-sail-riscv:
	./scripts/build_sail-riscv.sh

setup-isla:
	./scripts/build_isla.sh

gen-isla-traces-full:
	./scripts/gen_rv64gc_priv_instr_traces.sh 
	./scripts/gen_rv64gc_unpriv_instr_traces.sh &

isla-traces-test:
	mkdir -p isla_traces_test
	./scripts/gen_rv64gc_unpriv_instr_traces_test.sh 
	diff -bur isla_traces_test expected_results/isla_test_traces

isla-parse-test:
	python3 ./src/parse_test_isla_traces.py > parse_test_output.txt
	diff -bur parse_test_output.txt expected_results/parse_test_output.txt

run-sailor:
	mkdir -p CSVs
	python3 src/isla_csr_access.py
	python3 src/parse_isla_traces.py
	python3 src/analyzer.py
	diff -bur CSVs expected_results/reference_CSVs

generate-tests:
	python3 test-generator/generate-tests.py
	diff -bur test-generator/tests expected_results/tests

clean: 
	rm -f CSVs/*
	rm -f isla_traces_test/*
	rm -f test-generator/tests/*
