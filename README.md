# Sailor: Automated ISA-Inspection and Test-Generation for Secure Context Switching 

## IBM ACE RISC-V
This project is a part of IBM's [ACE RISC-V](https://github.com/IBM/ACE-RISCV) Confidential Computing Project. 

Directory Structure
-------------------
- isla          // Isla symbolic execution tool for Sail, modified to automatically generate traces for all RISC-V instructions with a new option   
- sail-riscv    // Sail RISC-V model, small modifications of resetting registers (corresponding to the latest sail model which conforms to the ISA specification more faithfully)  
- src          // Python scripts 
  - parse\_isla\_traces.py  // ISA Inspector part that generates ISA-insights by parsing Isla traces 
  - isla\_csr\_access.py    // Generate Isla CSR Access traces
  - analyzer.py             // Analyzer implementing the classifier algorithm 
- scripts               
- Makefile
- configs
- test-generator            // Automatic test generator 
  - tests                         // Generated tests
- patches 
  - sail-riscv-patch              // Patch applied to the Sail RISC-V Model ( in the sail-riscv dir)
  - isla-patch                    // Patch applied to Isla (in the isla dir) 
- expected\_results/        // Expected results to compare against

Getting started
---------------

## Setup dependencies 

We want to install the following versions of the toolchain: 
| Software | Version | 
|----|----|
| risc-v toolchain | 13.3.0 | 
| opam | 2.1.5 | 
| rustc | 1.86.0 | 
| ocaml | 4.14.1 |

Run the following command to install the dependencies.

``` make setup-dependencies ```

Further, download the Isla traces from google drive [here](https://drive.google.com/drive/folders/1FI_wnHABUfFjuzru2wMaTpUQf9I1Qw3r?usp=share_link).

## Applying patches and building Isla

Run the following commands.

```
make setup-sail-riscv
make setup-isla
```

## Running Basic Tests 

Run the following commands.

```
make isla-traces-test
make isla-parse-test
```

## Running Sailor 

Run the following commands.
```
make run-sailor
make generate-tests
```


# License
This repository is distributed under the terms of the Apache 2.0 License, see [LICENSE](LICENSE).
