<!-- Copyright (c) 2010-2025 Arm Limited or its affiliates. All rights reserved. -->
<!-- This document is Non-confidential and licensed under the BSD 3-clause license. -->
# Abstract Syntax Tree

Expressions describing conditionality or constraints of the AARCHMRS data are expressed using an Abstract Syntax Tree (AST) format.
This format mainly stems from two base AST nodes:

## $(AST.BinaryOp)

To represent expressions such as `A ==> B` or `A == B` etc. we  use $(AST.BinaryOp).

## $(AST.UnaryOp)
To represent expressions such as `NOT x`, `-2` or `!(A)` we use  $(AST.UnaryOp).

The rest of the AST models are used within these contexts.

!!! note

    While this `AST` is based on ASL, it is technically not ASL. It is only intended for use in AARCHMRS data.
    Please see [the ASL reference specification](https://github.com/herd/herdtools7/blob/master/asllib/AST.mli) if you need an official ASL AST.
