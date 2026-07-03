<!-- Copyright (c) 2010-2025 Arm Limited or its affiliates. All rights reserved. -->
<!-- This document is Non-confidential and licensed under the BSD 3-clause license. -->
render_when: Instruction.Encodeset.Encodeset

# Encodeset
Each instruction node uses a bit pattern that represents its encoding shape at that level.
It has two main properties:

 - `width`, which is the width of the encodeset in bits.
 - `values`, which is a list of fields (representing fields or bits) defined at the current level.

If part of an $(~Encodeset.Encodeset) is unspecified in both the current instruction node
and all of its parent nodes, that part is considered to be an "any-bit"
(`'1'` or `'0'`, usually denoted as `'x'`).

If part of the local $(~Encodeset.Encodeset) is unspecified but that same part has a
value specified in a parent node, the value of that part is inherited in the local $(~Encodeset.Encodeset).

For more information about the types of field, see the following:

