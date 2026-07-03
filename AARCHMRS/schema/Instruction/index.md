<!-- Copyright (c) 2010-2025 Arm Limited or its affiliates. All rights reserved. -->
<!-- This document is Non-confidential and licensed under the BSD 3-clause license. -->
render_when: Instruction.Instructions

# ISA Data Model User Guide

This guide introduces the AARCHMRS **I**nstruction **S**et **A**rchitecture (ISA) and the underlying
data models that represent it. The target audience is people who want to manipulate or read ISAs and their
contents programmatically.

This guide describes a fictitious ISA, named B64, which should not be conflated with a real ISA.

{% if internal -%}
!!! NOTE

    If you're looking for information about how to input instructions into AARCHMRS ISA, please
    follow this link to the [Input Layer Guide](../userguide/isa-input-layer.html).
{% endif -%}

[TOC]

## $(Instruction.Instructions) wrapper
$(~Instruction.Instructions) holds all instruction-related content. It has three properties:

* `instructions` - An array of instances of $(Instruction.InstructionSet), which is the root class for trees
  of instructions.
* `assembly_rules` - An object containing instances of $(Instruction.Rules.), keyed by `rule_id`.
* `operations` - An object containing instances of $(Instruction.Operation) or
  $(Instruction.OperationAlias), keyed by `operation_id`. Each $(~Instruction.Instruction) in the
  $(~Instruction.InstructionSet) is linked to an operation using an `operation_id`.

## Building the `B64` instruction set

The example below includes the following concepts, contained in an $(Instruction.Instructions) object:

  - The $(~Instruction.InstructionSet) node, which defines `B64`.
  - The $(~Instruction.Operation), which can define the default execute behavior of the instruction set.

include("examples/instructions/data_model/instructions.json")

In this example, there is a 32-bit instruction set named `B64`, which can have default behavior that here is defined in the operation identified by `unalloc`.

!!! NOTE

    Each instruction uses an $(Instruction.Encodeset.Encodeset) to define its bits. For more information,
    see $(~Instruction.Encodeset.).

!!! NOTE

    For ease of use from this point, instructions and operations are shown independently. In a real
    instruction set, they are defined within $(Instruction.Instructions), as described above.

### Adding instruction groups and individual instructions to `B64`

In the examples that follow, a group, `B64.arithmetic`, is added. It has two children -
`B64.arithmetic.register` and `B64.arithmetic.immediate` - and each has an `ADD` child and a `SUB` child.

The following is being represented:

```
B64 --> arithmetic --> register  --> ADD
                   |             \-> SUB
                   \-> immediate --> ADD
                                 \-> SUB
```

!!! WARNING

    The grouping shown above is useful for representational purposes, but the following is semantically
    equivalent:

        B64 --> ADD_register
            |-> SUB_register
            |-> ADD_immediate
            \-> SUB_immediate

    No architectural meaning should be inferred from syntactic differences between semantically equivalent
    arrangements of the tree.

The grouping provides an organisational representation of an architecture that may contain many
instructions. The grouping also allows common fields to be defined at the group level, which enables the use
of inheritance to reduce the duplicating of information in the data.

The four instructions in `B64.arithmetic` define the following:

  - `B64.arithmetic.register.ADD` provides a definition for `R[dst] = R[src0] + R[src1]`.
  - `B64.arithmetic.register.SUB` provides a definition for `R[dst] = R[src0] - R[src1]`.
  - `B64.arithmetic.immediate.ADD` provides a definition for `R[dst] = R[src0] + imm`.
  - `B64.arithmetic.immediate.SUB` provides a definition for `R[dst] = R[src0] - imm`.

The first and second operands of each are:

  - `dst` (short for "destination register").
  - `src0` (short for "first source register").

The third operand of `B64.arithmetic.register` instructions is `src1` (short for "second source register").
The third operand of `B64.arithmetic.immediate` instructions is `imm` (short for "immediate").

### `B64.arithmetic`

The `B64.arithmetic` group is first defined as follows:

include("examples/instructions/data_model/B64.arithmetic.json")

In the above:

 - The concatenation of bits `31:30, 25` is set to `'000'`, which is the opcode for all
   `arithmetic` instructions.
 - Bits `29:26` are redefined as `op0` and are used later to distinguish `ADD` and `SUB`.
 - The following fields are created:
    - `subtype` at bit `24` to distinguish between `register` and `immediate`
      variants.
    - `dst` at bits `23:16`.
    - `src0` at bits `15:8`.

### `B64.arithmetic.register` and `B64.arithmetic.immediate`

`B64.arithmetic.register` (a child of `B64.arithmetic`) is shown below:

include("examples/instructions/data_model/B64.arithmetic.register.json")

In the above:

 - Bit `24` is set to `'0'` to show the path to the `B64.arithmetic.register` group.
 - Bits `7:0` define the `src1` field.

`B64.arithmetic.immediate` (another child of `B64.arithmetic`) is shown below:

include("examples/instructions/data_model/B64.arithmetic.immediate.json")

In the above:

  - Bit `24` is set to `'1'` to show the path to the `B64.arithmetic.immediate` group.
  - Bit `7` is defined as `invert`. (When set to `'1'`, this is used to invert the results in the `dst`
    register.)
  - Bits `6:0` define the `imm` field.

### `B64.arithmetic.register.ADD`

#### `ADD_reg` operation

To reduce duplication of information in the data, $(Instruction.Operation) contains a single definition of
execute behavior that can be attached to more than one instruction.

!!! NOTE

    This is only a compression technique - defining the same behavior independently for each instruction
    would be semantically equivalent.

The following shows the "ADD (register)" operation (referenced as `ADD_reg`):

include("examples/instructions/data_model/operation.ADD_reg.json")

!!! NOTE

    The names `d`, `s0`, and `s1` come from the decode in the instruction, which is shown in the next
    section. The `R` refers to a general-purpose register in the `B64` architecture.

#### `ADD` instruction

The `ADD` instruction is defined under `B64.arithmetic.register` and then connected to its operation via the
`operation_id` key `"ADD_reg"`:

include("examples/instructions/data_model/B64.arithmetic.register.ADD.json")


The example above includes the following concepts:

  - A `decode` key, which defines the `ADD_reg` operation arguments. The decode key converts encoding
  fields `dst`, `src0`, and `src1` into integer values `d`, `s0`, and `s1`, respectively, so that they can
  be used to reference part of the `ADD_reg` operation:

```
R[d] = R[s0] + R[s1]
```

  - A should-be bit, on bit 29, denoted by the `should_be_mask` property.
  - `assemble`, which shows the translation from property to encoding (note the integer to bit conversions,
    as the value of the `operand.*.index` property is an integer but the encoding is bits).
  - `disassemble`, which shows the translation from encoding to property (note the inverse of the
    conversion that was done in `assemble`).
  - `properties` that further define the instruction. The meanings of these properties can be architecture
    specific, so they are not given in this schema. In the `B64` architecture, the following properties are used:
      - `isread` is true, meaning the register is read.
      - `iswritten` is true, meaning the register is written.
      - `index` is the index of the register file `R` that is accessed.

## Adding assembly to `B64`
An assembly layer can be added to an instruction, defining a human-friendly representation of the underlying
machine instruction. There might not be a one-to-one relationship between an assembly symbol and an encoding
field. For this reason, the property section of an $(~Instruction.Instruction) is used to hold intermediate
assembly data.

Here are some of the possible ways to describe the "ADD (register)" assembly:

```
ADD R5, R6, R9
ADD R[5], R[6], R[9]
ADD register 6 and register 9 and store the result in register 5
R5 = R6 + R9
```

This User Guide uses the first assembly notation - `ADD R5, R6, R9`. To define the assembly in the
`B64.arithmetic.register.ADD` instruction, the following are defined:

include("examples/instructions/data_model/assembly_rules.json")

!!! NOTE

    The content of the above example is added to the `assembly_rules` property of the
    $(Instruction.Instructions) mentioned in the "$(Instruction.Instructions) wrapper" section, above.

!!! WARNING

    The `assemble` and `disassemble` properties shown above are represented as strings, but in the data
    model they are represented as $(AST.StatementBlock). Strings are used here for readability.

The above example contains two types of $(Instruction.Rules.):

 - $(Instruction.Rules.Token):
    - `COMMA` is any token that matches the comma, followed by any trailing spaces.
    - `SPACE` is any token that matches one or more space characters.
    - `UInteger` is any token that matches an unsigned integer.
 - $(Instruction.Rules.Rule), for `Rd` (destination), `Rs0` (source1), and `Rs1` (source2):
    - `symbols` defines a parse rule in the following order:
        - `"R"`, which is an $(Instruction.Symbols.Literal).
        - `UInteger`, which is an $(Instruction.Symbols.RuleReference) that points to the `UInteger` token
          defined earlier.
    - `display` is an aid for rendering in documentation.
    - `assemble` shows the translation from symbol to property. The `UInteger`
      $(Instruction.Rules.Token) allows the integer from the assembly stream to be taken into the
      `operands.*.index` property.
    - `disassemble` shows the translation from property to symbol. It prints `"R"`, then the value
      stored in the `operands.*.index` property.

The defined rules are then connected to the assembly property of the `B64.arithmetic.register.ADD`
instruction using $(~Instruction.Symbols.RuleReference) as shown in the `assembly` of the instruction.

This allows rules to be reused when creating a `SUB (register)` instruction. For `ADD (immediate)`, the only
new rule required is for `"immediate"`.

## Alias
An example of an alias is "DOUBLE", which is an "ADD (register)" instruction where the `dst`, `src0`,
and `src1` fields have the same value. One operand is sufficient to disassemble this alias.

The following assemblies disassemble to the same instruction encoding:

```
DOUBLE X5
ADD X5, X5, X5
```

Both assemblies have the same behavior:

```
R[5] = R[5] + R[5]
```

To create this alias, a new rule, `RdRs0Rs1`, is needed:

include("examples/instructions/data_model/assembly_rules.RdRs0Rs1.json")

The main difference is that, to assemble, the rule `RdRs0Rs1` sets all the `operands.*.index` to the same
value. This is because the operand in the `DOUBLE` assembly maps to all three operand properties.

The alias `DOUBLE`, under `B64.arithmetic.register.ADD`, is now introduced:

include("examples/instructions/data_model/B64.arithmetic.register.ADD.DOUBLE.json")

In the above example:

  - `condition` indicates when the `B64.arithmetic.register.ADD.DOUBLE` alias is valid under
    `B64.arithmetic.register.ADD`.
  - `preferred` is set to true, which means in disassembly the `DOUBLE` alias is always preferred.
  - `operation_id` is set to `ADD_reg`, which is the same as `B64.arithmetic.register.ADD`.
  - Unlike $(~Instruction.Instruction), the $(Instruction.InstructionAlias) node cannot redefine the
    properties, as the behavior is the same.
  - `B64.arithmetic.register.ADD.DOUBLE` assembly is similar to `B64.arithmetic.register.ADD`, but rule
    `RdRs0Rs1` writes all the operands to the same value.

## Sub-instruction
A sub-instruction is a parent-child relationship between $(Instruction.Instruction) objects in which a child
node can override the behavior of its parent. This principle can be expanded to create many ancestor-child
relationships, permitting more than one level of sub-instruction.

-----

**See the following for more information:**

