SYM_INIT_FN = "__sym_ctor"

SYM_LIB_INIT = "_sym_initialize"

SYM_EXIT = ".LC_SYM_EX_{ex_label_addr}_{in_order}:"
SYM_ENTER = ".LC_SYM_ENTER_{enter_label_addr}_{in_order}: # {inst}"
SYM_CALL = ".LC_SYM_CALL_{call_label_addr}_{in_order}:"
SYM_REPEAT = ".LC_SYM_REPEAT_{repeat_label_addr}"

SYM_MODULE_INIT = [
    "\t.align 16, 0x90",  # 代码以16字节对齐，空余部分用nop指令替换
    "\tpushq %rax",
    ".Ltmp11:",
    "\tcallq {}@PLT".format(SYM_LIB_INIT),
    "\tpopq %rax",
    "\tretq",
]

SYM_START_STACK = [
    "\ttestb $0x, %al",

    "\tjz"
]

SYM_END_STACK = [
    "\taddq ${}, %rsp",

]

SYM_END_ADD_STACK_0 = [
    "\tpopq %rbp",
    "\tpopq %rbp",
    "\tjmp {label_addr}"
]

SYM_END_ADD_STACK_1 = [
    "\tpopq %rbp",
    "\tpopq 0x8(%rbp)",
    "\tjmp {label_addr}"
]

SYM_STACK_ALIGN_0 = [
    "\tmovq %rsp, %rax",
    "\tandb $0xf, %al",  # nz跳转
    "\tsetnz %al",
    "\tpushq %rax"
]

SYM_STACK_SUB = [
    "\tsubq $8, %rsp"
]

SYM_STACK_ALIGN_1 = [
    "\tpopq %rdi",
    "\ttestb $0x1, %dil"  # nz跳转
]

SYM_STACK_ADD = [
    "\taddq $8, %rsp"
]

# qsym后端将使用rsi，因此需处理两个参数寄存器
SYM_NOTIFY = [
    "\tleaq .LC{b_addr}(%rip), %rdi",
    "\tcall _sym_notify_{func}@PLT"
]

SYM_WRITE_MEMORY = [
    "\tmovq $0, {write_addr}",
    "\tmovq {write_data}, %rdx",
    "\tlea {write_addr}, %rdi",
    "\tmovl ${size}, %esi",
    "\tmovl $0x1, %ecx",
    "\tcall _sym_write_memory@PLT",
    # "\tmovq {value_addr}, %rax",
    # "\tmovq %rax, {write_addr}"
]

SYM_READ_MEMORY = [
    "\tmovq {read_addr}, %rdi",
    "\tmovl ${size}, %esi",
    "\tmovl $0x1, %edx",
    "\tcall _sym_read_memory@PLT",
    "\tmovq %rax, {read_res}"
]

SYM_GET_PARAM_EXP = [
    "\tmovl ${order}, %edi",
    "\tcall _sym_get_parameter_expression@PLT",
    "\tmovq %rax, {p_exp_addr}"
]

SYM_SET_PARAM_EXP = [
    "\tmovl ${order}, %edi",
    "\tmov{mne_bit} {exp_addr}, %{prefer_si}",
    "\tcall _sym_set_parameter_expression@PLT"
]

SYM_SET_RET_EXP = [
    "\tmov{mne_bit} {ret_exp}, %{prefer_di}",
    "\tcall _sym_set_return_expression@PLT"
]

SYM_GET_RET_EXP = [
    "\tcall _sym_get_return_expression@PLT",
    "\tmovq %rax, {memory}"
]

# 一元算术运算
SYM_BUILD_SIMPLE_OPERATION = [
    "\tmovq {op1}, %rdi",
    "\tcall _sym_build_{op_label}@PLT",
    "\tmovq %rax, {res}"
]

# 二元算术运算
SYM_BUILD_DYADIC_OPERATION = [
    "\tmovq {op1}, %rdi",
    "\tmovq {op2}, %rsi",
    "\tcall _sym_build_{op_label}@PLT",
    "\tmovq %rax, {res}"
]

# 比较
SYM_BUILD_CMP = [
    "\tmovq {op2}, %rdi",
    "\tmovq {op1}, %rsi",
    "\tcall _sym_build_{cmp_label}@PLT",
    "\tmovq %rax, {cond}"
]

SYM_JMP = [
    "\t{j_mne} {j_label_addr}",
]

SYM_PUSH_PATH_CONSTRAINT_PREFIX = [
    "\tset{cmp_mne} {flag_addr}"
]

SYM_PUSH_PATH_CONSTRAINT = [
    "\tmovq {cond}, %rdi",
    "\tmovzbl {flag_addr}, %esi",
    "\tleaq {j_label}(%rip), %rdx",
    "\tcall _sym_push_path_constraint@PLT"
]

SYM_OPERAND_PREFIX = [
    "\tmovq {judgement}, %rax",
    "\tcmpq $0, %rax",
    "\tmovq %rax, {op_addr}"
]

SYM_IS_BUILD = [
    "\tmovq {judgement}, %rax",
    "\tcmpq $1, %rax"
]

SYM_BUILD_EXT_OR_INT = [
    "\tmov{mne_bit} {value}, %{prefer_di}",
    "\tmovl ${sz}, %esi",
    "\tcall _sym_build_{func}@PLT",
    "\tmovq %rax, {op_addr}"
]

SYM_BUILD_INT128 = [
    "\tmovq {high_addr}, %rdi",
    "\tmovq {low_addr}, %rsi",
    "\tcall _sym_build_integer128@PLT",
    "\tmovq %rax, {int_res}"
]

SYM_BUILD_INT_TO_FLOAT = [
    
]

TRANSFER_MEMORY = [
    "\tmovq {exp_addr}, %rax",
    "\tmovq %rax, {transfer_addr}"
]