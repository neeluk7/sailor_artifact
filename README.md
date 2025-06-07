# Sailor: Automated ISA-Inspection and Test-Generation for Secure Context Switching 

Directory Structure
-------------------
- isla          // Isla symbolic execution tool for Sail, modified to automatically generate traces for all RISC-V instructions with a new option   
- sail-riscv    // Sail RISC-V model, small modifications of resetting registers (corresponding to the latest sail model which conforms to the ISA specification more faithfully)  
- src          // Python scripts 
  - parse\_isla\_traces.py  // ISA Inspector part that generates ISA-insights by parsing Isla traces 
  - isla\_csr\_access.py    // Generate Isla CSR Access traces
  - isla\_csr\_access\_dict\_to\_csvs.py 
  - analyzer.py             // Analyzer implementing the classifier algorithm 
- configs
  - rv64gc\_all\_opcodes.txt
- test-generator            // Automatic test generator 
  - tests                         // Generated tests
- patches 
  - sail-riscv-patch              // Patch applied to the Sail RISC-V Model ( in the sail-riscv dir)
  - isla-patch                    // Patch applied to Isla (in the isla dir) 

Getting started
---------------

## Setup dependencies 

### Python 

A nice way to install and switch between Python versions is using [pyenv](https://medium.com/@aashari/easy-to-follow-guide-of-how-to-install-pyenv-on-ubuntu-a3730af8d7f0).

Run the following commands: 
```
sudo apt update
sudo apt install -y make build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev wget curl llvm libncursesw5-dev xz-utils tk-dev libxml2-dev libxmlsec1-dev libffi-dev liblzma-dev
curl https://pyenv.run | bash
```

On MacOS, you can run: 
```
brew install pyenv
```

Once pyenv is setup, add it to your system's PATH. For more details, check the [Pyenv setup guide](https://medium.com/@aashari/easy-to-follow-guide-of-how-to-install-pyenv-on-ubuntu-a3730af8d7f0) blogpost on Medium.  

Now you can use pyenv to install a specific version of python. 

```
pyenv install 3.12.3
pyenv local 3.12.3
``` 

### Sail 

We want to install the following versions of the toolchain: 

| Software | Version | 
|----|----|
| opam | 2.1.5 | 
| sail | 0.18.0 |
| ocaml | 4.14.1 |

[Here](https://github.com/rems-project/sail/blob/sail2/INSTALL.md) are the instructions to install Sail using opam.

Here's the output I see when I run the `which sail` command: 
```
/home/usr/.opam/default/bin/sail
```

Here's the first line of output when I run the `sail --help` command: 
```
Sail 0.18.0
```

Setting up Isla
---------------

Refer [Isla Readme](https://github.com/rems-project/isla/tree/master)

### Install rust: (unix)

`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`

### Change rustc version

`rustup default 1.70.0`

### Install z3 (ensure to setup opam apriori)

To install a specific version of z3.
`opam install z3=4.12.6`

The above still leads to linker errors for me. In that case try building it from [source](https://github.com/Z3Prover/z3).

### Building z3 from source.

Step 1: Get source for the 4.12.6 version release.

Step 2: Set up Python2:

```
brew install pyenv
pyenv install 2.7.18
export PATH="$(pyenv root)/shims:${PATH}"
echo 'PATH=$(pyenv root)/shims:$PATH' >> ~/.zshrc
pyenv init
```

Add the path init to ~/.zprofile and ~/.zshrc (or ~/.bashprofile and ~/.bashrc, depending on your shell), then source them.
Use the following to switch to python2.

`pyenv shell 2.7.18`

Pyenv is a nice way to manage multiple python versions and quickly switch between them using the previous command.

Step 3: Now follow the 'Building Z3 using make and GCC/Clang' section to install z3.

Note: We just used g++ compiler instead of clang.

Once this step is complete, we should have the libz3.so/dylib file to link against. Copy it to the isla root directory.
Then, also set the LD\_LIBRARY\_PATH to the isla root dir.

### Building and running Isla

Try `cargo build --release` for isla and see above regarding building z3 from source in case of linker errors.

Make sure to clone the isla-snapshots repository. After this step, running the isla-footprint command for Arm "add" instruction (the example from the readme in the isla repo) works.

### Running isla-footprint for RISC-V

Ideally we should rebuild the Isla IR snapshot for RISC-V to reflect the latest sail model. Refer to the [Isla README](https://github.com/rems-project/isla?tab=readme-ov-file#model-snapshots) to do that. 
It requires building sail from the sail2 branch of the github repository (instead of directly using the opam installed sail).
Also read this discussion for generating isla footprints for RISC-V in one of their past [github issues](https://github.com/rems-project/isla/issues/82) (opened by me).
TLDR: You can use isla-sail to regenerate the IR, but the order of the sail model files matters in the command, it must be the same as what is used to compile the sail model.

Once you can generate the traces and have setup the environment for Isla correctly, you can proceed to apply our patches to Isla.


