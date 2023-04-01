from collections import defaultdict
from archinfo import ArchAMD64
import copy

operation_mnemonics = [
    "add", "adc", "inc", "aaa", "daa",
    "sub", "sbb", "dec", "aas", "das", "cmp",
    "mul", "imul", "aam",
    "div", "idiv", "aad",
    "neg", "cbw", "cwd", "cwde", "cdq",
    "not", "and", "or", "xor", "test",
    "shl", "sal", "shr", "sar",
    "rol", "rcl", "ror", "rcr"
]


regs = ["rdi", "rsi", "rcx", "rdx", "rbx", "r8", "r9", "r10",
        "r11", "r12", "r13", "r14", "r15", "rax", "rbp", "rsp"]

param_regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]


# Get the register map
regmap = defaultdict(lambda: defaultdict(dict))
regindex = dict()
amd64 = ArchAMD64()
# 初始化各个寄存器在不同的位下的不同名称
for reg in amd64.register_list:
    if reg.general_purpose:
        for subr in reg.subregisters:
            base = subr[1]
            sz = subr[2] * 8
            regmap[reg.name][base][sz] = subr[0]
            regindex[subr[0]] = (reg.name, base, sz)
        if reg.name in [
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]:
            regmap[reg.name][0][32] = reg.name + "d"
            regmap[reg.name][0][16] = reg.name + "w"
            regmap[reg.name][0][8] = reg.name + "b"

            regindex[regmap[reg.name][0][32]] = (reg.name, 0, 32)
            regindex[regmap[reg.name][0][16]] = (reg.name, 0, 16)
            regindex[regmap[reg.name][0][8]] = (reg.name, 0, 8)
        if reg.name == "rbp":
            regmap[reg.name][0][32] = "ebp"
            regmap[reg.name][0][16] = "bp"
            regmap[reg.name][0][8] = "bpl"

            regindex[regmap[reg.name][0][32]] = (reg.name, 0, 32)
            regindex[regmap[reg.name][0][16]] = (reg.name, 0, 16)
            regindex[regmap[reg.name][0][8]] = (reg.name, 0, 8)

        regmap[reg.name][0][64] = reg.name
        regindex[reg.name] = (reg.name, 0, 64)

        # 浮点寄存器
        for j in range(16):
            xmm_name = "xmm{}".format(j)
            regmap[xmm_name][0][64] = xmm_name
            regindex[xmm_name] = (xmm_name, 0, 64)


def _get_subreg32(regname):
    return regmap[regname][0][32]


def _get_subreg16(regname):
    return regmap[regname][0][16]


def _get_subreg8l(regname):
    return regmap[regname][0][8]  # 低8位


def _get_subreg8h(regname):
    return regmap[regname][1][8]  # 高8位


def has_reg(op_str, reg):
    if op_str.find(reg) != -1:
        return reg
    elif op_str.find(_get_subreg32(reg)) != -1:
        return _get_subreg32(reg)
    if op_str.find(_get_subreg8l(reg)) != -1:
        return _get_subreg8l(reg)
    elif 1 in regmap[reg].keys() and op_str.find(_get_subreg8h(reg)) != -1:
        return _get_subreg8h(reg)
    elif op_str.find(_get_subreg16(reg)) != -1:
        return _get_subreg16(reg)
    else:
        return ""


def merge_basic_block_infos(fn, idxs_bb, jmp_labels):
    jmp_from_idxs = dict()
    if not idxs_bb:
        return jmp_from_idxs

    # 获取某个地址对应的前置跳转指令
    for idx, inst in enumerate(fn.cache):

        if ".L{}".format(hex(inst.address)[2:]) in jmp_labels.keys():
            if idx not in idxs_bb:
                idxs_bb.append(idx)

            jmp_from_idxs[idx] = jmp_labels[".L{}".format(hex(inst.address)[2:])]

    return jmp_from_idxs


def get_basic_blocks(idxs_bb, m):
    bb_intervals = dict()
    idxs_bb = sorted(idxs_bb)
    for i in range(len(idxs_bb)):
        if i < len(idxs_bb) - 1:
            bb_intervals[idxs_bb[i]] = (idxs_bb[i], idxs_bb[i + 1])
        elif idxs_bb[i] < m:
            bb_intervals[idxs_bb[i]] = (idxs_bb[i], m)

    return bb_intervals, idxs_bb[0] if len(idxs_bb) > 0 else None


def topological_sort(idxs_bb, jmp_from_idxs, m):
    # 使用伪拓扑排序获得控制流图的依赖关系
    sort_bb_intervals = list()
    jmp_from_idxs = copy.deepcopy(jmp_from_idxs)
    bb_intervals, _ = get_basic_blocks(idxs_bb, m)
    bb_intervals = list(bb_intervals.values())

    if len(bb_intervals) == 0:
        end_interval = None
    else:
        end_interval = bb_intervals[len(bb_intervals) - 1]

    while len(bb_intervals) > 0:
        rm_interval = None
        n = len(bb_intervals)
        for i in range(n):
            interval = bb_intervals[i]
            if interval[0] not in jmp_from_idxs.keys() or interval[0] in jmp_from_idxs and len(
                    jmp_from_idxs[interval[0]]) == 0:
                sort_bb_intervals.append(interval)
                rm_interval = interval
                break

        if rm_interval is None:  # 有跳转环存在，直接拆除环
            rm_interval = bb_intervals[0]
            sort_bb_intervals.append(rm_interval)

        # 删除该节点和它的关联关系
        bb_intervals.remove(rm_interval)
        for idx in jmp_from_idxs.keys():
            if rm_interval[0] - 1 in jmp_from_idxs[idx]:
                jmp_from_idxs[idx].remove(rm_interval[0] - 1)

    return sort_bb_intervals, end_interval


def handle_get_operands(inst_op_str):
    if inst_op_str == "":
        return []

    l_loc, r_loc = inst_op_str.find("("), inst_op_str.find(")")
    if l_loc != -1:
        if "," in inst_op_str[:l_loc]:  # 说明op2有()
            operands = [op.strip() for op in inst_op_str.split(",", 1)]
        else:
            operands = list(reversed([op[::-1].strip() for op in inst_op_str[::-1].split(",", 1)]))
    else:
        operands = [op.strip() for op in inst_op_str.split(",")]

    return operands


def get_op_type(op):
    return "r" if op[0] == "%" else "n" if op[0] == "$" else "m"


def is_assgin(mnemonic):
    return mnemonic.startswith("mov") or not mnemonic.startswith("leave") and mnemonic.startswith("lea")


def is_operation(mnemonic):
    return mnemonic[:3] in operation_mnemonics or mnemonic[:4] in operation_mnemonics


def is_nop(mnemonic):
    return mnemonic.startswith("nop")


def is_call(mnemonic):
    return mnemonic.startswith("call")


def is_jmp(mnemonic):
    return mnemonic.startswith("j")


def is_only_jmp(mnemonic):
    return mnemonic.startswith("jmp")


def is_cmp(mnemonic):
    return mnemonic.startswith("cmp")


def is_set_flags(mnemonic):
    return mnemonic.startswith("set")


def is_push_or_pop(mnemonic):
    return mnemonic.startswith("push") or mnemonic.startswith("pop")


def is_ret(mnemonic):
    return mnemonic.startswith("retq")


def has_segment_reg(op_str):
    return "%cs:" in op_str or "%ds:" in op_str \
           or "%ss:" in op_str or "%es:" in op_str \
           or "%fs:" in op_str or "%gs:" in op_str


def get_to_use_regs(fn, bb_intervals, jmp_from_idxs):
    to_use_regs = dict()

    for l_idx, r_idx in bb_intervals:
        to_use_regs[l_idx] = list()
        if l_idx in jmp_from_idxs.keys():  # 有前置节点时才会提前预存寄存器表达式
            for r in regs[:-1]:
                for idx in range(l_idx, r_idx):
                    instruction = fn.cache[idx]
                    ops = handle_get_operands(instruction.op_str)

                    if is_operation(instruction.mnemonic) and has_reg(instruction.op_str, r) != "":
                        if get_op_type(ops[0]) == "r" and has_reg(ops[0], r) != "" or \
                                len(ops) > 1 and get_op_type(ops[1]) and has_reg(ops[1], r) != "":
                            # 未使用内存，运算中需要表达式
                            to_use_regs[l_idx].append(r)

                            break

                    elif is_assgin(instruction.mnemonic) and has_reg(instruction.op_str, r) != "":
                        if has_reg(ops[0], r) != "" and "(" not in instruction.op_str \
                                and "$" not in instruction.op_str:
                            # 非内存操作，存在表达式传递
                            to_use_regs[l_idx].append(r)

                        break

                    elif has_reg(instruction.op_str, r) != "":
                        break

    return to_use_regs


def get_free_registers(idx, fn):
    if idx in fn.analysis['free_registers']:
        free_registers = fn.analysis['free_registers'][idx]
        free_registers = list(free_registers)
        if "rflags" in free_registers:
            free_registers.remove("rflags")
        return free_registers
    else:
        print("[x] Missing free reglist in cache. Regenerate!")
        return []


def get_use_not_define_regs(fn, bb_intervals):
    use_not_define_regs = dict()
    for l_idx, r_idx in bb_intervals:
        use_not_define_regs[l_idx] = list()

        for r in regs[:-1]:
            for idx in range(l_idx, r_idx):
                instruction = fn.cache[idx]
                ops = handle_get_operands(instruction.op_str)

                if is_operation(instruction.mnemonic) and has_reg(instruction.op_str, r) != "":
                    if has_reg(ops[0], r) != "" or len(ops) > 1 and has_reg(ops[1], r) != "":
                        use_not_define_regs[l_idx].append(r)

                    break

                elif is_assgin(instruction.mnemonic) and has_reg(instruction.op_str, r) != "" is not None:
                    if has_reg(ops[0], r) != "":
                        use_not_define_regs[l_idx].append(r)

                    break

                elif r == "rax" and is_call(instruction.mnemonic):
                    # 存在call，则后续使用rax基本上是返回值
                    break

                elif has_reg(instruction.op_str, r) != "":
                    break

    return use_not_define_regs
