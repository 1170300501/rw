from librw_x64.container import DataCell, InstrumentedInstruction, Function
from rwtools_x64.utils import *
from . import snippets as sp

intercepted_functions = ["malloc", "calloc", "mmap", "mmap64", "open", "read", "lseek",
                         "lseek64", "fopen", "fopen64", "fread", "fseek", "fseeko", "rewind",
                         "fseeko64", "getc", "ungetc", "memcpy", "memset", "strncpy", "strchr",
                         "memcmp", "memmove", "ntohl", "fgets", "fgetc", "getchar",
                         "fread_unlocked", "fetc_unlocked", "fgets_unlocked"]


j_mne_antonym = {
    "jz": "jnz", "jc": "jnc", "jo": "jno", "js": "jns", "jp": "jnp",  # 标志位
    "je": "jne",  # 相等比较
    "ja": "jbe", "jb": "jae", "jae": "jb", "jbe": "ja",  # 无符号数比较
    "jg": "jle", "jl": "jge", "jge": "jl", "jle": "jg"  # 有符号数比较
}

jn_mne_antonym = dict(zip(j_mne_antonym.values(), j_mne_antonym.keys()))

caller_store_data_regs = ["r10", "r11"]  # 其他寄存器遵循被调用者规则，由被调用者保存
callee_store_data_regs = ["r12", "r13", "r14", "r15"]
bits_mne_map = {8: "b", 16: "w", 32: "l", 64: "q"}
mne_bits_map = dict(zip(bits_mne_map.values(), bits_mne_map.keys()))

SYM_GLOBAL_DS_BASE = 0x3000000000000000
SYM_INIT_LOC = 0x1000000000000000

RBP_MEMORY = "-{}(%rbp)"
RSP_MEMORY = "{}(%rsp)"


class Sym_Instrument:

    def __init__(self, rewriter):
        self.origin_stack_size = None
        self.stack_size = 0
        self.use_rbp = 0
        # -1 表示没有任何rsp、rbp的使用（包括插桩），不做任何处理
        # 0  表示使用rsp
        # 1  表示使用rbp
        # 2  表示有rbp赋值使用，需复杂处理
        self.rewriter = rewriter

        self.instrument_orders = dict()  # 存放各条指令插入情况，用于标号生成

    def get_store_addr(self, block=8, origin_sz=None):
        if origin_sz is None:
            self.stack_size += block

        sz = self.stack_size if origin_sz is None else origin_sz
        addr = RBP_MEMORY.format(hex(sz))

        return addr

    def bypassed(self, instruction):
        return instruction.mnemonic.startswith("nop")

    def not_cond_inst(self, mnemonic):
        # todo 简易的筛除，后续还需优化
        return is_assgin(mnemonic) or is_nop(mnemonic) or is_jmp(mnemonic) \
               or is_set_flags(mnemonic) or is_push_or_pop(mnemonic)

    def get_stack_loc_8_align(self, fn):
        max_stack_loc = 0
        sub_size = 0

        for idx, instruction in enumerate(fn.cache):
            if "(%rbp)" in instruction.op_str or "(%rsp)" in instruction.op_str:
                if "(%rbp)" in instruction.op_str:
                    self.use_rbp = 1
                else:
                    self.use_rbp = 0
                operands = handle_get_operands(instruction.op_str)
                stack_relative = operands[0] if "(%rbp)" in operands[0] or "(%rsp)" in operands[0] else operands[1]
                if stack_relative[0] == "(":
                    continue

                if self.use_rbp == 1:
                    stack_loc = int(stack_relative[stack_relative.find("-") + 1:stack_relative.find("(%rbp")], 16)
                elif self.use_rbp == 0:
                    stack_loc = int(stack_relative[:stack_relative.find("(%rsp")], 16)

                max_stack_loc = stack_loc if max_stack_loc < stack_loc else max_stack_loc

            elif instruction.mnemonic.startswith("subq") and "%rsp" in instruction.op_str[-4:]:
                # has_rsp_expand = True
                sz_str = handle_get_operands(instruction.op_str)[0][1:]
                if sz_str[0] == "-":
                    sub_size += int(sz_str[1:], 16) if sz_str[1:3] == "0x" else int(sz_str)
                else:
                    sub_size += int(sz_str, 16) if sz_str[0:2] == "0x" else int(sz_str)

        if max_stack_loc % 8 != 0:  # 8字节对齐
            max_stack_loc += max_stack_loc % 8

        # if has_rsp_expand and self.use_rbp == -1:
        #     self.use_rbp = 0

        return max(max_stack_loc, sub_size)

    def handle_specific_param_reg(self, p_reg, i, reg_instrumentation):
        base = self.origin_stack_size + 8 if self.use_rbp == 1 else 8
        memory = self.get_store_addr(origin_sz=base + 8 * i)
        reg_instrumentation.insert(0, "\tmovq %{reg}, {memory}".format(
            reg=p_reg,
            memory=memory
        ))
        reg_instrumentation.append("\tmovq {memory}, %{reg}".format(
            memory=memory,
            reg=p_reg
        ))

    def handle_param_regs(self, idx, fn, reg_instrumentation, is_call):
        # 处理参数使用的寄存器
        free_registers = get_free_registers(idx, fn)
        rbp_reg = fn.cache[idx].rbp_reg

        for i, param_reg in enumerate(param_regs):
            if param_reg not in free_registers or rbp_reg == param_reg or is_call and i == 0:
                self.handle_specific_param_reg(param_reg, i + 1, reg_instrumentation)

        # 处理返回值的寄存器
        self.handle_specific_param_reg("rax", 7, reg_instrumentation)

        if is_call:
            # 被调用者数据处理寄存器需要提前预存
            for i, caller_store_data_reg in enumerate(caller_store_data_regs):
                if caller_store_data_reg not in free_registers or rbp_reg == caller_store_data_reg:
                    self.handle_specific_param_reg(caller_store_data_reg, i + 8, reg_instrumentation)

    def combine_instrumentation(self, idx, fn, local_instrument, sym_instrument):
        reg_instrument = []
        in_order = self.instrument_orders.get(idx, 0)
        inst = fn.cache[idx]

        call_idx = -1
        for i, si in enumerate(sym_instrument):
            if si.startswith("\tcall"):
                call_idx = i

        if call_idx != -1:
            call = sp.SYM_CALL.format(
                in_order=in_order,
                call_label_addr=hex(inst.address)[2:]
            )
            before = sym_instrument[:call_idx]
            after = sym_instrument[call_idx + 1:]
            sym_instrument = sym_instrument[call_idx:call_idx + 1]

        self.handle_param_regs(idx, fn, reg_instrument, call_idx != -1)

        def stack_align(stack_align_instrumentation, stack_op_instrumentation, j_mne, label):
            # 用于保证栈是16字节对齐
            if len(stack_align_instrumentation) > 2:
                local_instrument.extend(stack_align_instrumentation[:-1])
            else:
                local_instrument.extend(stack_align_instrumentation)

            local_instrument.append(sp.SYM_JMP[0].format(
                j_mne=j_mne,
                j_label_addr=label[:-1]
            ))
            local_instrument.extend(stack_op_instrumentation)
            local_instrument.append(label)

            if len(stack_align_instrumentation) > 2:
                local_instrument.append(stack_align_instrumentation[-1])

        # 合并指令
        enter = sp.SYM_ENTER.format(
            in_order=in_order,
            enter_label_addr=hex(inst.address)[2:],
            inst=inst
        )
        ex = sp.SYM_EXIT.format(
            in_order=in_order,
            ex_label_addr=inst.address
        )

        local_instrument.append(enter)
        local_instrument.extend(reg_instrument[:len(reg_instrument) // 2])

        # 当存在调用sym函数，需要保证栈对齐
        if call_idx != -1:
            local_instrument.extend(before)
            stack_align(sp.SYM_STACK_ALIGN_0, sp.SYM_STACK_SUB, "jnz", call)

        local_instrument.extend(sym_instrument)

        # 恢复栈值
        if call_idx != -1:
            stack_align(sp.SYM_STACK_ALIGN_1, sp.SYM_STACK_ADD, "jnz", ex)
            local_instrument.extend(after)
        else:
            local_instrument.append(ex)

        local_instrument.extend(reg_instrument[len(reg_instrument) // 2:])

        self.instrument_orders[idx] = self.instrument_orders.get(idx, 0) + 1

        return enter, ex

    def replace_nop(self, instruction):
        instruction.mnemonic = "nop"
        instruction.op_str = ""
        ins_sz = instruction.sz

        nops = list()
        for i in range(ins_sz - 1):
            nops.append("\tnop")

        instruction.instrument_after("\n".join(nops))

    def add_sym_basic_block(self, fn, idxs_bb):
        for idx in idxs_bb:
            if idx >= len(fn.cache):
                continue

            inst_bb = fn.cache[idx]
            bb_instrument = list()
            self.combine_instrumentation(idx, fn, bb_instrument, sp.SYM_NOTIFY)
            inst_bb.instrument_before("\n".join(bb_instrument).format(
                b_addr=hex(inst_bb.address)[2:],
                func="basic_block"
            ), 0)

    def add_sym_path_constraint(self, fn, idx_pc_exp_map, jmp_labels):
        idx_labels = dict()
        for v, l in jmp_labels.items():
            for k in l:
                idx_labels[k] = v

        for idx in idx_pc_exp_map.keys():
            path_constraint_instrument = list()
            instruction = fn.cache[idx]

            self.combine_instrumentation(idx, fn, path_constraint_instrument, sp.SYM_PUSH_PATH_CONSTRAINT)
            instruction.instrument_after("\n".join(path_constraint_instrument).format(
                flag_addr=idx_pc_exp_map[idx][1],
                cond=idx_pc_exp_map[idx][0],
                j_label=idx_labels[idx]
            ))

            instruction.instrument_after("\ttestb $0x1, {flag_addr}".format(
                flag_addr=idx_pc_exp_map[idx][1]
            ))

            instruction.instrument_after("\n".join(sp.SYM_JMP).format(
                j_mne="jz",
                j_label_addr=idx_labels[idx]
            ))

    def handle_param_exp(self, reg_exp_addrs, not_skip_idx, fn):
        used_regs = set()

        # 获取参数是连续的指令
        for pr_idx, p_reg in enumerate(param_regs):
            cut_p_reg = p_reg[1:] if len(p_reg) > 2 else p_reg

            for i in range(10):
                if not_skip_idx + i >= len(fn.cache):
                    break

                instruction = fn.cache[not_skip_idx + i]

                if cut_p_reg in instruction.op_str.split(",")[0] and cut_p_reg not in used_regs:
                    used_regs.add(cut_p_reg)

                    p_exp_addr = self.get_store_addr()
                    p_exp_instrument = list()
                    self.combine_instrumentation(not_skip_idx + i, fn, p_exp_instrument, sp.SYM_GET_PARAM_EXP)

                    instruction.instrument_before("\n".join(p_exp_instrument).format(
                        order=hex(pr_idx),
                        p_exp_addr=p_exp_addr
                    ))

                    reg_exp_addrs[p_reg] = p_exp_addr
                    break

            if cut_p_reg not in used_regs:  # 参数读取完毕
                break

    def handle_ret_exp(self, ret_idx, ret_hex_address, fn):
        idxs_ret_exp = list()
        ret_instrument = list()
        mne_bit = "q"
        sz = 64
        write_addr = self.get_store_addr()
        ret_addr = self.get_store_addr()

        for idx, instruction in enumerate(fn.cache):
            if ret_hex_address in instruction.op_str or idx == ret_idx:  # 这是一条跳往return的指令
                r_idx = idx - 1
                idxs_ret_exp.append(r_idx)  # 存放可能产生返回值的指令

                inst_ret_exp = fn.cache[r_idx]
                if inst_ret_exp.mnemonic[-1] not in mne_bits_map.keys():  # 该指令不是一个可以获取sz的指令
                    continue

                mne_bit = inst_ret_exp.ret_mne
                sz = mne_bits_map[mne_bit]

        for idx_ret_exp in idxs_ret_exp:
            inst_ret_exp = fn.cache[idx_ret_exp]
            ret_exp_instrumentation = list()
            ret_is_build_instrumentation = list()

            write_exp = inst_ret_exp.rax_exp_addr if inst_ret_exp.rax_exp_addr else "$0x0"

            if write_exp != "$0x0":
                sym_instrumentation = list()
                sym_instrumentation.extend(sp.SYM_IS_BUILD)
                sym_instrumentation.extend(sp.SYM_JMP)
                sym_instrumentation.append("\tmovq $0x0, {judgement}")
                _, ex = self.combine_instrumentation(idx_ret_exp, fn, ret_is_build_instrumentation, sym_instrumentation)

                inst_ret_exp.instrument_after("\n".join(ret_is_build_instrumentation).format(
                    judgement=write_exp,
                    j_mne="jne",
                    j_label_addr=ex.split(":")[0]
                ))

            self.combine_instrumentation(idx_ret_exp, fn, ret_exp_instrumentation, sp.SYM_WRITE_MEMORY)

            inst_ret_exp.instrument_after("\n".join(ret_exp_instrumentation).format(
                mne_bit=mne_bit,
                write_data=write_exp,
                prefer_dx=regmap["rdx"][0][sz],
                write_addr=write_addr,
                size=hex(sz // 8)
            ))

        # 在末尾处设置read、set_ret_exp
        inst_ret = fn.cache[ret_idx]
        self.combine_instrumentation(ret_idx, fn, ret_instrument, sp.SYM_READ_MEMORY)
        inst_ret.instrument_before("\n".join(ret_instrument).format(
            read_addr=write_addr,
            size=hex(sz // 8),
            read_res=ret_addr,
        ))

        ret_instrument.clear()
        self.combine_instrumentation(ret_idx, fn, ret_instrument, sp.SYM_SET_RET_EXP)

        inst_ret.instrument_before("\n".join(ret_instrument).format(
            mne_bit=bits_mne_map[sz],
            ret_exp=ret_addr,
            prefer_di=regmap["rdi"][0][sz]
        ))

    def handle_build_operands(self, memory_exp_addrs, reg_read_addrs, reg_exp_addrs, op, idx, j_label_addr,
                              fn, sym_instrument, args, is_cmp=False):
        prefix_instrumentation = list()
        instruction = fn.cache[idx]
        op_type = get_op_type(op)
        exp_type = ""

        exp = "$0x0"
        value = op
        args["mne_bit"] = "q"
        args["prefer_di"] = "rdi"
        if op in instruction.param_addrs.keys():  # 已设置参数表达式，一般将用于比较
            exp = instruction.param_addrs[op]
            value = instruction.param_addrs[op]
            exp_type = "p_exp"
        elif op_type == "r":
            if not has_segment_reg(op):  # 不是段寄存器
                v_reg, _, v_sz = regindex[op[1:]]

                if instruction.rbp_reg == regindex[op[1:]][0]:
                    # 此操作数实际为rbp，将替换为rbp的表达式计算
                    v_reg = "rbp"

                if v_reg in reg_exp_addrs.keys():  # 运算产生的表达式
                    exp = reg_exp_addrs[v_reg]
                    value = op
                    exp_type = "op_exp"

                    if args["func"] != "sext":
                        # 不存在movzlq指令，movl即可将高位置0
                        args["mne_bit"] = "z{}q".format(bits_mne_map[v_sz]) if v_sz < 32 else bits_mne_map[v_sz]
                        args["prefer_di"] = args["prefer_di"] if v_sz < 32 else regmap["rdi"][0][v_sz]

                elif v_reg in reg_read_addrs.keys():  # 读取内存产生的表达式
                    reg_read_info = reg_read_addrs[v_reg]
                    exp = reg_read_info[1]
                    value = reg_read_info[0]
                    exp_type = "read_exp"

                else:  # 没有任何对应的表达式
                    value = op
                    if args["func"] != "sext":
                        args["mne_bit"] = "z{}q".format(bits_mne_map[v_sz]) if v_sz < 32 else bits_mne_map[v_sz]
                        args["prefer_di"] = args["prefer_di"] if v_sz < 32 else regmap["rdi"][0][v_sz]

        elif op in memory_exp_addrs.keys():  # 写入内存产生的该内存的表达式
            exp = memory_exp_addrs[op]
            value = exp
            exp_type = "m_exp"

        elif op_type == "m":  # 内存操作，但没有表达式
            if args["func"] != "sext":
                args["mne_bit"] = "z{}q".format(bits_mne_map[args["sz"]]) if args["sz"] < 32 else bits_mne_map[
                    args["sz"]]
                args["prefer_di"] = args["prefer_di"] if args["sz"] < 32 else regmap["rdi"][0][args["sz"]]

        # 操作数构建：
        # 当构建比较表达式，
        #   1.有立即数的情况：
        #       a.立即数需构建integer，无需判空。
        #       b.若比较的字节数小于4（32位）：
        #           i. 当另一个操作数有表达式，以表达式为参数调用sext扩展位数
        #           ii.当另一个操作数不存在表达式，将不会构建比较表达式
        #       c.否则只需使用另一操作数已有的read或exp表达式即可，需要判空。
        #   2.仅有寄存器或内存的情况：均需构建integer，若已有表达式可以直接使用，均需要判空。
        #   3.当判空成功时，将跳过整个比较的构建。
        # 当构建运算表达式，
        #   1.操作数为立即数：构建integer
        #   2.操作数为寄存器：
        #       a.该寄存器的值源于某个内存（read_exp），需要对read_exp构建integer，需要判空。
        #       b.该寄存器的值源于某个运算（op_exp），可以直接使用，但需要判空。
        #       c.该寄存器的值只来源于赋值，构建integer，无需判空。
        #   3.操作数为内存：
        #       a.该内存的值已被构建出表达式（exp），可以直接使用，需要判空。
        #       b.该内存的值只源于赋值，需要构建integer，无需判空。
        #   4.当判空成功时，将跳过整个运算的构建。

        def handle_is_null():
            enter, _ = self.combine_instrumentation(idx, fn, prefix_instrumentation, sp.SYM_OPERAND_PREFIX)

            instruction.instrument_before("\n".join(prefix_instrumentation).format(
                judgement=exp,
                op_addr=ret_addr
            ))

            instruction.instrument_before("\n".join(sp.SYM_JMP).format(
                j_mne="je",
                j_label_addr=j_label_addr
            ))

            return enter

        def handle_is_build():
            build_instrumentation = list()
            enter, _ = self.combine_instrumentation(idx, fn, build_instrumentation, sp.SYM_IS_BUILD)

            instruction.instrument_before("\n".join(build_instrumentation).format(
                judgement=exp
            ))

            # 若已构建，需要加入表达式的生成
            instruction.instrument_before("\n".join(sp.SYM_JMP).format(
                j_mne="jne",
                j_label_addr="@@"  # 表示待完成
            ))

            return len(instruction.before) - 1

        def handle_operand(op_v):
            int_instrumentation = list()
            args["value"] = op_v
            args["op_addr"] = ret_addr

            enter, _ = self.combine_instrumentation(idx, fn, int_instrumentation, sym_instrument)
            instruction.instrument_before("\n".join(int_instrumentation).format(**args))

            return enter

        insert_jmp_enter_idx = -1
        if op_type != "n" and exp_type != "":
            if is_cmp:  # 比较
                if args["func"] == "sext":
                    ret_addr = self.get_store_addr()
                    et = handle_is_null()
                    handle_operand(exp)
                elif exp_type == "op_exp":
                    ret_addr = exp
                    et = handle_is_null()
                    insert_jmp_enter_idx = handle_is_build()
                    handle_operand(value)
                else:
                    ret_addr = exp
                    et = handle_is_null()
            else:  # 运算
                if exp_type == "op_exp":
                    ret_addr = exp
                    et = handle_is_null()
                    insert_jmp_enter_idx = handle_is_build()
                else:
                    ret_addr = self.get_store_addr()
                    et = handle_is_null()

                handle_operand(value)
        else:
            ret_addr = self.get_store_addr()
            if args["func"] == "sext":
                et = handle_is_null()
                handle_operand(ret_addr)
            else:
                et = handle_operand(value)

        if not is_cmp:  # op_exp来源于运算
            if op_type != "n":
                if op_type == "m":
                    memory_exp_addrs[op] = ret_addr
                elif not has_segment_reg(op):
                    reg_exp_addrs[v_reg] = ret_addr

        return ret_addr, insert_jmp_enter_idx, et

    def handle_operation_res_exp(self, instruction, cmp_order, res_addr):
        # 处理运算中的结果存放地址
        for idx, insts in enumerate(instruction.before):
            if cmp_order <= 0:
                return

            cmp_loc = insts.find("\tcmp")
            if cmp_loc == -1:
                continue

            cmp_order -= 1
            if cmp_order == 0:  # 到指定的cmp指令处，再处理
                instruction.before[idx] = insts[:cmp_loc] + "\tmovq $0, {}\n".format(res_addr) + insts[cmp_loc:]

    def get_to_use_reg_infos(self, fn, bb_intervals, jmp_from_idxs):
        to_use_regs_exp_addr = dict()
        to_use_regs = get_to_use_regs(fn, bb_intervals, jmp_from_idxs)

        for l_idx, to_use_regs in to_use_regs.items():
            to_use_regs_exp_addr[l_idx] = dict()
            for to_use_reg in to_use_regs:
                to_use_regs_exp_addr[l_idx][to_use_reg] = self.get_store_addr()

        return to_use_regs_exp_addr

    def init_to_use_reg_infos(self, idx, fn, to_use_regs_exp_addr):
        if idx is None:
            return

        for _, reg_addrs in to_use_regs_exp_addr.items():
            for exp_addr in reg_addrs.values():
                fn.cache[idx].instrument_after("\tmovq $1, {}".format(exp_addr))

    def save_to_use_reg_infos(self, r_idx, fn, to_use_regs_exp_addr, jmp_from_idxs, reg_exp_addrs):
        jmp_to_idx = None
        for idx, jmp_froms in jmp_from_idxs.items():
            if r_idx - 1 in jmp_froms:
                jmp_to_idx = idx

        def transfer(last_idx, to_idx):
            if to_idx == len(fn.cache):
                return

            for to_use_reg in to_use_regs_exp_addr[to_idx].keys():
                if to_use_reg in reg_exp_addrs.keys():
                    last_instruction = fn.cache[last_idx]
                    transfer_addr = to_use_regs_exp_addr[to_idx][to_use_reg]

                    transfer_instrumentation = list()
                    self.combine_instrumentation(last_idx, fn, transfer_instrumentation, sp.TRANSFER_MEMORY)
                    last_instruction.instrument_before("\n".join(transfer_instrumentation).format(
                        exp_addr=reg_exp_addrs[to_use_reg],
                        transfer_addr=transfer_addr
                    ))

        # 存档跳转后将被使用的表达式
        if jmp_to_idx is not None:
            transfer(r_idx - 1, jmp_to_idx)

        # 存档顺序执行将被使用的表达式
        if not is_only_jmp(fn.cache[r_idx - 1].mnemonic):
            transfer(r_idx - 1, r_idx)

    def handle_assignment(self, idx, fn, memory_exp_addrs, reg_read_addrs, reg_exp_addrs):
        local_instrumentation = list()
        instruction = fn.cache[idx]
        operands = handle_get_operands(instruction.op_str)
        op1_type, op2_type = get_op_type(operands[0]), get_op_type(operands[1])

        if op2_type == "r":
            op2_reg = regindex[operands[1][1:]][0]

            # 当两个寄存器相同，无需删除
            if not (op1_type == "r" and not has_segment_reg(operands[0]) and regindex[operands[0][1:]][0] == op2_reg):
                if op2_reg in reg_read_addrs.keys():
                    reg_read_addrs.pop(op2_reg)

                if op2_reg in reg_exp_addrs.keys():
                    reg_exp_addrs.pop(op2_reg)

        # 获取数据大小
        sz = 64
        if len(instruction.mnemonic) > 3 and instruction.mnemonic[3] in mne_bits_map.keys():
            sz = mne_bits_map[instruction.mnemonic[-1]]
        elif len(instruction.mnemonic) > 3 and \
                (instruction.mnemonic[3] == "z" or instruction.mnemonic[3] == "s"):
            sz = mne_bits_map[instruction.mnemonic[4]]
        # elif "xmm" in instruction.op_str:
        #     sz = 128

        block = max(sz, 64) // 8

        if has_segment_reg(instruction.op_str):  # 有段寄存器，不处理
            pass
        elif "(" in instruction.op_str:  # 涉及内存
            if op1_type == "m":  # read
                reg, base, _ = regindex[operands[1][1:]]

                save_addr = self.get_store_addr(block)
                read_value = self.get_store_addr(block)
                read_res = self.get_store_addr(block)

                # 提前保存地址，以供read使用
                save_instrument = list()
                self.combine_instrumentation(idx, fn, save_instrument,
                                             ["\tleaq {op1}, %rax", "\tmovq %rax, {save_addr}"])

                instruction.instrument_before("\n".join(save_instrument).format(
                    op1=operands[0],
                    save_addr=save_addr
                ))

                # 保存读取值
                instruction.instrument_after("\tmovq %{reg}, {value_addr}".format(
                    reg=reg,
                    value_addr=read_value
                ))

                self.combine_instrumentation(idx, fn, local_instrumentation, sp.SYM_READ_MEMORY)
                instruction.instrument_after("\n".join(local_instrumentation).format(
                    read_addr=save_addr,
                    size=hex(sz // 8),
                    read_res=read_res
                ))

                # 恢复读取值
                instruction.instrument_after("\tmovq {value_addr}, %{reg}".format(
                    reg=reg,
                    value_addr=read_value
                ))

                # 记录reg来源的表达式地址
                reg_read_addrs[reg] = (read_value, read_res)

            else:  # write
                write_addr = self.get_store_addr(block)

                if op1_type == "n":  # 立即数写入
                    write_data = "$0x0"
                else:
                    reg, base, op1_sz = regindex[operands[0][1:]]
                    write_data = reg_exp_addrs[reg] if reg in reg_exp_addrs.keys() else "$0x0"

                op1_sz = 32 if write_data == "$0x0" else op1_sz

                self.combine_instrumentation(idx + 1, fn, local_instrumentation, sp.SYM_WRITE_MEMORY)
                instruction.instrument_after("\n".join(local_instrumentation).format(
                    mne_bit=bits_mne_map[op1_sz],
                    write_data=write_data,
                    prefer_dx=regmap["rdx"][0][op1_sz],
                    write_addr=write_addr,
                    size=hex(sz // 8)
                ))

                memory_exp_addrs[operands[1]] = write_addr

        elif "$" in instruction.op_str:  # 立即数传递到寄存器
            pass

        else:  # 两个寄存器之间的传递
            op1_reg, op2_reg = regindex[operands[0][1:]][0], regindex[operands[1][1:]][0]

            if len(instruction.mnemonic) > 3 and instruction.mnemonic[3] == "s" and op1_reg in reg_read_addrs.keys():
                # sext
                sext_instrumentation = list()
                op2_addr = self.get_store_addr()
                self.combine_instrumentation(idx, fn, sext_instrumentation, sp.SYM_BUILD_EXT_OR_INT)
                instruction.instrument_before("\n".join(sext_instrumentation).format(
                    mne_bit="q",
                    value=reg_read_addrs[op1_reg][1],
                    prefer_di="rdi",
                    sz=mne_bits_map[instruction.mnemonic[5]] - sz,
                    func="sext",
                    op_addr=op2_addr
                ))

                reg_read_addrs.pop(op1_reg)
                reg_exp_addrs[op2_reg] = op2_addr
            else:

                if op1_reg in reg_read_addrs.keys():
                    reg_read_addrs[op2_reg] = reg_read_addrs[op1_reg]

                if op1_reg in reg_exp_addrs.keys():
                    reg_exp_addrs[op2_reg] = reg_exp_addrs[op1_reg]

    def handle_call(self, idx, bb_interval, fn, memory_exp_addrs, reg_exp_addrs, to_use_regs_exp_addr, jmp_from_idxs):
        instruction = fn.cache[idx]
        param_inst_idx = dict()
        l_idx, r_idx = bb_interval
        func_need_exp = False

        # 如果调用函数是内置函数，修改成libSymRuntime里对应的函数
        op_str_parts = instruction.op_str.split("@")
        if op_str_parts[0] in intercepted_functions:
            instruction.op_str = op_str_parts[0] + "_symbolized@" + op_str_parts[1]
            func_need_exp = True
        elif instruction.op_str.startswith(".L"):
            func_need_exp = True

        if not func_need_exp:
            return

        # 倒退寻找参数相关指令
        for p_reg in param_regs:
            p_reg = p_reg if len(p_reg) < 3 else p_reg[1:]

            for t_idx, target_instruction in enumerate(fn.cache[idx - 1:max(idx - 20, l_idx - 1):-1]):
                if target_instruction.mnemonic.startswith("call") or target_instruction.mnemonic.startswith("jmp"):
                    # 只在本函数范围内，且没有无条件跳转
                    break

                if target_instruction.mnemonic.startswith("push"):
                    continue

                if p_reg not in param_inst_idx.keys() and p_reg in target_instruction.op_str[-2:]:
                    param_inst_idx[p_reg] = idx - 1 - t_idx
                    break

            if p_reg not in param_inst_idx.keys():  # 寄存器参数传递读取完毕
                break

        # print(param_inst_idx)

        first_p_idx = idx

        # 按参数顺序处理
        for order, p_reg in enumerate(param_regs):
            p_reg = p_reg if len(p_reg) < 3 else p_reg[1:]
            if p_reg not in param_inst_idx.keys():
                break

            p_idx = param_inst_idx[p_reg]
            p_instruction = fn.cache[p_idx]
            operands = handle_get_operands(p_instruction.op_str)
            exp_addr = reg_exp_addrs[regindex[operands[-1][1:]][0]] \
                if regindex[operands[-1][1:]][0] in reg_exp_addrs.keys() else "$0x0"

            # 找到最靠前的传参指令的位置
            first_p_idx = p_idx if first_p_idx > p_idx else first_p_idx

            set_p_instrumentation = list()

            if exp_addr != "$0x0":  # 判断是否已构建
                is_build_instrumentation = list()
                is_build_instrumentation.extend(sp.SYM_IS_BUILD)
                is_build_instrumentation.extend(sp.SYM_JMP)
                is_build_instrumentation.append("movq $0x0, {}".format(exp_addr))
                _, ex = self.combine_instrumentation(p_idx, fn, set_p_instrumentation, is_build_instrumentation)
                p_instruction.instrument_after("\n".join(set_p_instrumentation).format(
                    judgement=exp_addr,
                    j_mne="jne",
                    j_label_addr=ex.split(":")[0]
                ))

                set_p_instrumentation.clear()

            self.combine_instrumentation(p_idx + 1, fn, set_p_instrumentation, sp.SYM_SET_PARAM_EXP)

            # 插入set_param_exp
            p_instruction.instrument_after("\n".join(set_p_instrumentation).format(
                order=hex(order),
                mne_bit=p_instruction.mnemonic[-1],
                exp_addr=exp_addr,
                prefer_si=regmap["rsi"][0][mne_bits_map[p_instruction.mnemonic[-1]]]
            ))

        # TODO 参数大于6时
        if len(param_inst_idx) == 6:
            order = 6
            for t_idx, target_instruction in enumerate(fn.cache[idx - 1:max(idx - 20, 0):-1]):
                if target_instruction.mnemonic.startswith("call") or target_instruction.mnemonic.startswith("jmp"):
                    # 只在本函数范围内，且没有无条件跳转
                    break

                if target_instruction.mnemonic.startswith("push"):
                    op = target_instruction.op_str
                    op_type = get_op_type(op)
                    exp_addr = reg_exp_addrs[regindex[op[1:]][0]] \
                        if op_type == "r" and regindex[op[1:]][0] in reg_exp_addrs.keys() else \
                        memory_exp_addrs[op] if op_type == "m" and op in memory_exp_addrs.keys() else "$0x0"

                    # 找到最靠前的传参指令的位置
                    first_p_idx = t_idx if first_p_idx > t_idx else first_p_idx

                    set_p_instrumentation = list()
                    self.combine_instrumentation(t_idx + 1, fn, set_p_instrumentation, sp.SYM_SET_PARAM_EXP)

                    # 插入set_param_exp
                    target_instruction.instrument_after("\n".join(set_p_instrumentation).format(
                        order=hex(order),
                        mne_bit=target_instruction.mnemonic[-1],
                        exp_addr=exp_addr,
                        prefer_si=regmap["rsi"][0][mne_bits_map[target_instruction.mnemonic[-1]]]
                    ))

                    order += 1

        # 在第一条传参指令前插入notify_call
        pre_p_inst = fn.cache[first_p_idx]
        notify_instrument = list()

        self.combine_instrumentation(first_p_idx, fn, notify_instrument, sp.SYM_NOTIFY)
        pre_p_inst.instrument_before("\n".join(notify_instrument).format(
            in_order=self.instrument_orders.get(first_p_idx),
            b_addr=hex(instruction.address)[2:],
            func="call"
        ), order=0)

        # notify_ret
        notify_instrument.clear()
        self.combine_instrumentation(idx, fn, notify_instrument, sp.SYM_NOTIFY)
        instruction.instrument_after("\n".join(notify_instrument).format(
            in_order=self.instrument_orders.get(idx, 0),
            b_addr=hex(instruction.address)[2:],
            func="ret"
        ))

        # 在基本块内检查是否存在返回值
        use_retv = False
        for i in range(idx + 1, max(idx + 11, r_idx)):
            if i == len(fn.cache) or use_retv:
                break

            inst_check = fn.cache[i]
            if is_assgin(inst_check.mnemonic):
                if has_reg(inst_check.op_str.split(",")[0], "rax") != "":
                    # 当此前不存在赋值到ax且将ax值赋出时，说明存在返回值
                    use_retv = True
                elif has_reg(inst_check.op_str[-2:], "rax") != "":
                    # 出现赋值到ax，但还未有ax值赋出和使用，说明没有返回值
                    break

            elif (is_operation(inst_check.mnemonic)
                  or is_set_flags(inst_check.mnemonic)
                  or is_jmp(inst_check.mnemonic)
                  or is_call(inst_check.mnemonic)):
                if has_reg(inst_check.op_str, "rax") != "":
                    # 对于运算、转移、置位指令，若使用了ax，说明存在返回值
                    use_retv = True
                if is_call(inst_check.mnemonic) \
                        or is_only_jmp(inst_check.mnemonic):
                    # 另一个call之后是其他函数的返回值
                    break

        # 检查跳转块是否使用返回值
        for j_to_idx in jmp_from_idxs.keys():
            if r_idx - 1 in jmp_from_idxs[j_to_idx]:
                use_retv = use_retv or "rax" in to_use_regs_exp_addr[j_to_idx].keys()
                break

        # 检查后续块是否使用返回值
        if r_idx != len(fn.cache):
            use_retv = use_retv or "rax" in to_use_regs_exp_addr[r_idx].keys()

        # 返回rax表达式，同时更新rax表达式地址
        if use_retv:
            ret_instrument = list()
            self.combine_instrumentation(idx, fn, ret_instrument, sp.SYM_SET_RET_EXP)
            instruction.instrument_before("\n".join(ret_instrument).format(
                mne_bit="l",
                ret_exp="$0x0",
                prefer_di="edi"
            ), order=0)

            ret_instrument.clear()
            memory = self.get_store_addr()
            self.combine_instrumentation(idx, fn, ret_instrument, sp.SYM_GET_RET_EXP)
            fn.cache[idx].instrument_after("\n".join(ret_instrument).format(
                memory=memory
            ))

            reg_exp_addrs["rax"] = memory

        elif "rax" in reg_exp_addrs.keys():
            # 删除rax对应的表达式
            reg_exp_addrs.pop("rax")

    def handle_comparison(self, idx, fn, memory_exp_addrs, reg_read_addrs, reg_exp_addrs, idx_pc_exp_map):
        local_instrumentation = list()
        instruction = fn.cache[idx]

        if is_only_jmp(instruction.mnemonic):
            return -1, False

        if instruction.mnemonic.startswith("jne") or instruction.mnemonic.startswith("jnz"):  # build_equal
            cmp_label = "equal"
        elif instruction.mnemonic.startswith("je") or instruction.mnemonic.startswith("jz"):  # build_not_equal
            cmp_label = "not_equal"

        elif instruction.mnemonic.startswith("jle"):
            cmp_label = "signed_greater_than"
        elif instruction.mnemonic.startswith("jl"):
            cmp_label = "signed_greater_equal"
        elif instruction.mnemonic.startswith("jge"):
            cmp_label = "signed_less_than"
        elif instruction.mnemonic.startswith("jg"):
            cmp_label = "signed_less_equal"

        elif instruction.mnemonic.startswith("jbe"):
            cmp_label = "unsigned_greater_than"
        elif instruction.mnemonic.startswith("jb"):
            cmp_label = "unsigned_greater_equal"
        elif instruction.mnemonic.startswith("jae"):
            cmp_label = "unsigned_less_than"
        elif instruction.mnemonic.startswith("ja"):
            cmp_label = "unsigned_less_equal"

        else:
            print("[x] comparison miss: {}".format(instruction))
            return -1, False

        c_idx = idx
        for _ in range(10):
            c_idx -= 1
            c_inst = fn.cache[c_idx]
            if c_idx < 0 or not self.not_cond_inst(c_inst.mnemonic):
                break

            if "xmm" in c_inst.op_str or "st" in c_inst.op_str:
                return -1, False

        # 暂时只考虑整型比较
        cond_instruction = fn.cache[c_idx]

        # todo 对一些函数做额外处理

        operands = handle_get_operands(cond_instruction.op_str)
        sz = mne_bits_map[cond_instruction.mnemonic[-1]]
        j_label_addr = sp.SYM_REPEAT.format(repeat_label_addr=hex(cond_instruction.address)[2:])

        args1 = dict()
        args2 = dict()

        if cond_instruction.mnemonic.startswith("test"):
            operands = [operands[1], "$0"]

        if ("$" in cond_instruction.op_str or cond_instruction.mnemonic.startswith("test")) and sz < 32:
            args1["sz"] = 32
            args2["sz"] = 32 - sz
            args1["func"] = "integer"
            args2["func"] = "sext"
            if "$" in operands[1]:
                args1, args2 = args2, args1
        else:
            args1["sz"] = sz
            args1["func"] = "integer"
            args2 = args1

        op1_addr, i_idx1, _ = self.handle_build_operands(memory_exp_addrs, reg_read_addrs, reg_exp_addrs,
                                                         operands[0], c_idx, j_label_addr, fn,
                                                         sp.SYM_BUILD_EXT_OR_INT, args1, is_cmp=True)

        op2_addr, i_idx2, enter1 = self.handle_build_operands(memory_exp_addrs, reg_read_addrs, reg_exp_addrs,
                                                              operands[1], c_idx, j_label_addr, fn,
                                                              sp.SYM_BUILD_EXT_OR_INT, args2, is_cmp=True)

        cond_addr = self.get_store_addr()
        flag_addr = self.get_store_addr()
        enter2, _ = self.combine_instrumentation(c_idx, fn, local_instrumentation, sp.SYM_BUILD_CMP)
        cond_instruction.instrument_before("\n".join(local_instrumentation).format(
            op1=op1_addr,
            op2=op2_addr,
            cmp_label=cmp_label,
            cond=cond_addr
        ))

        if i_idx1 != -1:
            cond_instruction.before[i_idx1] = cond_instruction.before[i_idx1].replace("@@", enter1.split(":")[0])

        if i_idx2 != -1:
            cond_instruction.before[i_idx2] = cond_instruction.before[i_idx2].replace("@@", enter2.split(":")[0])

        if cond_instruction.mnemonic.startswith("test"):
            op1_type = get_op_type(operands[0])
            if op1_type == "r":
                if cond_instruction.rbp_reg == regindex[operands[0][1:]][0]:  # 替换的情况，需要修改rbp
                    reg_exp_addrs.pop("rbp")
                else:
                    reg_exp_addrs.pop(regindex[operands[0][1:]][0])
            elif op1_type == "m":
                memory_exp_addrs.pop(operands[0])

        if j_label_addr + ":" not in cond_instruction.after:  # 若已有可以直接使用
            cond_instruction.instrument_after(j_label_addr + ":")
            cond_instruction.instrument_after("\t" + str(cond_instruction).split(": ")[1])
            path_idx = len(cond_instruction.after)
        else:
            path_idx = cond_instruction.after.index(j_label_addr + ":") + 2

        # 将标志位设置在flag_addr
        cmp_mne = j_mne_antonym[instruction.mnemonic] if "n" not in instruction.mnemonic \
            else jn_mne_antonym[instruction.mnemonic]
        cond_instruction.instrument_after("\n".join(sp.SYM_PUSH_PATH_CONSTRAINT_PREFIX).format(
            cmp_mne=cmp_mne[1:],
            flag_addr=flag_addr,
        ), order=path_idx)

        # 对于比较指令，需要对存放比较表达式的地址预先赋值为0，避免当表达式不存在时，后续需要使用该地址出错
        self.handle_operation_res_exp(cond_instruction, 1, cond_addr)
        self.handle_operation_res_exp(cond_instruction, 2, cond_addr)

        idx_pc_exp_map[idx] = (cond_addr, flag_addr)

        return c_idx, True

    def handle_operation(self, idx, fn, memory_exp_addrs, reg_read_addrs, reg_exp_addrs):
        local_instrumentation = list()
        instruction = fn.cache[idx]
        op_reverse = False

        # 获取运算
        if instruction.mnemonic.startswith("add"):
            op_label = "add"
        elif instruction.mnemonic.startswith("sub"):
            op_label = "sub"
            op_reverse = True
        elif instruction.mnemonic.startswith("imul") or instruction.mnemonic.startswith("mul"):
            op_label = "mul"
        elif instruction.mnemonic.startswith("idiv"):
            op_label = "signed_div"
            op_reverse = True
        elif instruction.mnemonic.startswith("div"):
            op_label = "unsigned_div"
            op_reverse = True

        elif instruction.mnemonic.startswith("shl") or instruction.mnemonic.startswith("sal"):
            op_label = "shift_left"
        elif instruction.mnemonic.startswith("shr"):
            op_label = "logical_shift_right"
        elif instruction.mnemonic.startswith("sar"):
            op_label = "arithmetic_shift_right"

        elif instruction.mnemonic.startswith("xor"):
            op_label = "xor"
        elif instruction.mnemonic.startswith("or"):
            op_label = "or"
        elif instruction.mnemonic.startswith("and"):
            op_label = "and"
        elif instruction.mnemonic.startswith("test"):
            op_label = "and"

        elif instruction.mnemonic.startswith("not"):
            op_label = "not"
        elif instruction.mnemonic.startswith("neg"):
            op_label = "neg"

        else:
            print("[x] operation miss: {}".format(instruction))
            return False

        operands = handle_get_operands(instruction.op_str)
        sz = mne_bits_map[instruction.mnemonic[-1]]
        j_label_addr = sp.SYM_REPEAT.format(repeat_label_addr=hex(instruction.address)[2:])
        args = dict()
        args["sz"] = sz
        args["func"] = "integer"

        op1_addr, i_idx1, _ = self.handle_build_operands(memory_exp_addrs, reg_read_addrs, reg_exp_addrs,
                                                         operands[0], idx, j_label_addr, fn,
                                                         sp.SYM_BUILD_EXT_OR_INT, args)

        if len(operands) == 1:  # 单操作数，imul、idiv，目的操作数是rax
            if "div" in op_label:
                op2_addr = op1_addr
                op1_instrument = list()

                if sz == 64:
                    op1_addr = self.get_store_addr()
                    i_idx2 = -1
                    enter1, _ = self.combine_instrumentation(idx, fn, op1_instrument, sp.SYM_BUILD_INT128)
                    instruction.instrument_before("\n".join(op1_instrument).format(
                        high_addr="%rdx",
                        low_addr="%rax",
                        int_sz=hex(sz),
                        int_res=op1_addr
                    ))
                else:
                    value = self.get_store_addr()
                    args = dict()
                    args["sz"] = sz
                    args["func"] = "integer"

                    op1_instrument.append("\tmov{mne} %{ax}, {memory}".format(
                        mne=bits_mne_map[sz],
                        ax=regmap["rax"][0][sz],
                        memory=self.get_store_addr()
                    ))

                    op1_instrument.append("\tmov{mne} %{dx}, {memory}".format(
                        mne=bits_mne_map[sz],
                        dx=regmap["rdx"][0][sz],
                        memory=value
                    ))

                    op1_instrument.extend(sp.SYM_BUILD_EXT_OR_INT)

                    op1_addr, i_idx2, enter1 = self.handle_build_operands(memory_exp_addrs, reg_read_addrs,
                                                                          reg_exp_addrs,
                                                                          value, idx, j_label_addr, fn,
                                                                          sp.SYM_BUILD_EXT_OR_INT, args)

                res_op = "%rax"

                sym_instrumentation = sp.SYM_BUILD_DYADIC_OPERATION

            elif "mul" in op_label:
                op2_addr = op1_addr
                res_op = "%rax"
                op1_addr, i_idx2, enter1 = self.handle_build_operands(memory_exp_addrs, reg_read_addrs, reg_exp_addrs,
                                                                      res_op, idx, j_label_addr, fn,
                                                                      sp.SYM_BUILD_EXT_OR_INT, args)

                sym_instrumentation = sp.SYM_BUILD_DYADIC_OPERATION

            else:
                op2_addr = ""
                i_idx2 = -1
                enter1 = None
                res_op = "%" + regindex[operands[-1][1:]][0] if operands[-1][1:] in regindex.keys() \
                    else operands[-1]

                sym_instrumentation = sp.SYM_BUILD_SIMPLE_OPERATION

        elif len(operands) == 2:  # 双操作数，源操作数和目的操作数
            op2_addr, i_idx2, enter1 = self.handle_build_operands(memory_exp_addrs, reg_read_addrs, reg_exp_addrs,
                                                                  operands[1], idx, j_label_addr, fn,
                                                                  sp.SYM_BUILD_EXT_OR_INT, args)

            res_op = "%" + regindex[operands[-1][1:]][0] if operands[-1][1:] in regindex.keys() \
                else operands[-1]

            sym_instrumentation = sp.SYM_BUILD_DYADIC_OPERATION
        else:
            op2_addr, i_idx2, enter1 = self.handle_build_operands(memory_exp_addrs, reg_read_addrs, reg_exp_addrs,
                                                                  operands[1], idx, j_label_addr, fn,
                                                                  sp.SYM_BUILD_EXT_OR_INT, args)

            res_op = "%" + regindex[operands[2][1:]][0] if operands[2][1:] in regindex.keys() \
                else operands[2]

            sym_instrumentation = sp.SYM_BUILD_DYADIC_OPERATION

        # 存放两个参数的表达式地址，便于后续
        instruction.param_addrs[operands[0]] = op1_addr
        if len(operands) > 1:
            instruction.param_addrs[operands[1]] = op2_addr

        if op_reverse:  # 特殊情况需要翻转op1和op2的位置
            op1_addr, op2_addr = op2_addr, op1_addr

        res_addr = self.get_store_addr()
        enter2, _ = self.combine_instrumentation(idx, fn, local_instrumentation, sym_instrumentation)
        instruction.instrument_before("\n".join(local_instrumentation).format(
            op1=op1_addr,
            op2=op2_addr,
            op_label=op_label,
            res=res_addr
        ))

        if i_idx1 != -1:
            enter1 = enter2 if enter1 is None else enter1
            instruction.before[i_idx1] = instruction.before[i_idx1].replace("@@", enter1.split(":")[0])

        if i_idx2 != -1:
            instruction.before[i_idx2] = instruction.before[i_idx2].replace("@@", enter2.split(":")[0])

        instruction.instrument_after(j_label_addr + ":")
        instruction.instrument_after("\t" + str(instruction).split(": ")[1])

        # 对于运算指令，需要对存放结果表达式的地址预先赋值为0，避免当表达式不存在时，后续需要使用该地址出错
        self.handle_operation_res_exp(instruction, 1, res_addr)
        self.handle_operation_res_exp(instruction, 2, res_addr)

        # 更新表达式地址
        if instruction.rbp_reg == res_op[1:]:
            # 目的操作数实际上是rbp，则需要修改rbp对应的表达式
            res_op = "%rbp"

        if get_op_type(res_op) == "r":
            reg_exp_addrs[res_op[1:]] = res_addr
        else:
            memory_exp_addrs[res_op] = res_addr

        # 此时op2不再表示内存读取值，删除相应信息
        if res_op[1:] in reg_read_addrs.keys():
            reg_read_addrs.pop(res_op[1:])

        return True

    def add_symbolic_instrumentation(self):
        for addr, fn in self.rewriter.container.functions.items():
            self.use_rbp = 0
            jmp_labels = dict()
            idx_pc_exp_map = dict()
            instructions_remove = list()
            idxs_bb = []
            idxs_end = set()
            has_retq = False
            is_main = fn.name == "main"
            print("\n[*] function analyze: {}\n".format(fn.name))

            # 同时预先获取栈大小和栈内存使用情况
            origin_stack_size = self.get_stack_loc_8_align(fn)

            self.origin_stack_size = origin_stack_size
            if self.use_rbp == 0:
                self.stack_size = 88
                idx_start = 0
                idxs_bb.append(idx_start)
            else:
                self.stack_size = origin_stack_size + 88
                idx_start = None

            # 获得控制流图
            for idx, instruction in enumerate(fn.cache):

                if idx_start is None and \
                        (instruction.mnemonic.startswith("subq") and "%rsp" in instruction.op_str[-4:]
                         or instruction.mnemonic.startswith("movq") and instruction.op_str == "%rsp, %rbp"):
                    # subq xx, %rsp / movq %rsp, %rbp
                    if instruction.mnemonic.startswith("movq") and instruction.op_str == "%rsp, %rbp":
                        if fn.cache[idx + 1].mnemonic.startswith("subq") and "%rsp" in fn.cache[idx + 1].op_str[-4:]:
                            idxs_bb.append(idx + 2)
                        else:
                            idxs_bb.append(idx + 1)
                    else:
                        idxs_bb.append(idx + 1)

                    idx_start = idx

                if is_jmp(instruction.mnemonic):
                    idxs_bb.append(idx + 1)
                    if instruction.op_str not in jmp_labels.keys():
                        jmp_labels[instruction.op_str] = [idx]
                    else:
                        jmp_labels[instruction.op_str].append(idx)

                if instruction.mnemonic.startswith("retq"):  # 具有返回指令，可以处理栈
                    has_retq = True

            if not has_retq:
                # 没有返回指令，通常为过渡函数，此时无需处理任何指令
                continue

            jmp_from_idxs = merge_basic_block_infos(fn, idxs_bb, jmp_labels)
            bb_intervals, end_interval = topological_sort(idxs_bb, jmp_from_idxs, len(fn.cache))
            to_use_regs_exp_addr = self.get_to_use_reg_infos(fn, bb_intervals, jmp_from_idxs)

            for bb_interval in bb_intervals:
                l_idx, r_idx = bb_interval
                one_end = True  # 一个基本块中最多有一个结束语句
                idx_end = None
                reg_exp_addrs = copy.deepcopy(to_use_regs_exp_addr[l_idx])
                reg_read_addrs = dict()
                memory_exp_addrs = dict()

                for idx, instruction in enumerate(fn.cache[l_idx:r_idx]):
                    this_idx = l_idx + idx
                    print(instruction)

                    if "xmm" in instruction.op_str:
                        continue

                    if self.use_rbp == 0 and instruction.mnemonic.startswith("retq"):
                        idx_end = this_idx

                    if this_idx == idx_start:
                        # 对非main函数处理输入参数表达式
                        if not is_main:
                            self.handle_param_exp(reg_exp_addrs, this_idx, fn)

                    if instruction.mnemonic.startswith("subq") and "%rsp" in instruction.op_str[-4:] \
                            or instruction.mnemonic.startswith("addq") and "%rsp" in instruction.op_str[-4:] \
                            or instruction.mnemonic.startswith("movq") and instruction.op_str == "%rsp, %rbp" \
                            or instruction.mnemonic.startswith("leave") \
                            or instruction.mnemonic.startswith("popq") and "rbp" in instruction.op_str:

                        if self.use_rbp == 1:
                            # 结束部分
                            if instruction.mnemonic.startswith("leave") \
                                    or instruction.mnemonic.startswith("popq") and "rbp" in instruction.op_str \
                                    or instruction.mnemonic.startswith("addq") and "%rsp" in instruction.op_str[-4:]:

                                if l_idx == end_interval[0] \
                                        or end_interval[0] in jmp_from_idxs.keys() and r_idx - 1 in jmp_from_idxs[
                                    end_interval[0]] \
                                        or r_idx == end_interval[0] and not is_only_jmp(fn.cache[r_idx - 1].mnemonic):
                                    # 在结束部分之前
                                    if one_end or not one_end \
                                            and instruction.mnemonic.startswith("addq") \
                                            and "%rsp" in instruction.op_str[-4:]:
                                        idx_end = this_idx

                                    one_end = False

                        if instruction.mnemonic.startswith("subq") or instruction.mnemonic.startswith("addq") \
                                or instruction.mnemonic.startswith("movq"):
                            continue

                    if self.bypassed(instruction):
                        continue

                    if self.use_rbp == 0 and has_reg(instruction.op_str, "rbp") != "" \
                            and not is_push_or_pop(instruction.mnemonic):  # 需要伪造rbp
                        rbp_reg = None
                        free_regs = get_free_registers(this_idx, fn)
                        if "rbp" in free_regs:
                            free_regs.remove("rbp")

                        # 保证即将替换的寄存器未使用
                        while len(free_regs) > 0 and has_reg(instruction.op_str, free_regs[0]):
                            free_regs.pop(0)

                        if free_regs:  # 有空闲寄存器，用于替换rbp的位置
                            rbp_reg = free_regs[0]
                        else:  # 否则找到当前指令未使用的寄存器，用于替换
                            for reg in regs[:-2]:
                                if has_reg(instruction.op_str, reg) == "":
                                    rbp_reg = reg
                                    break

                        instruction.rbp_reg = rbp_reg
                        if instruction.rbp_reg is None:
                            continue

                        operands = handle_get_operands(instruction.op_str)

                        for operand in operands:
                            rbp_str = has_reg(operand, "rbp")
                            if rbp_str != "":
                                _, _, sz = regindex[rbp_str]
                                instruction.op_str = instruction.op_str.replace(rbp_str, regmap[rbp_reg][0][sz])

                                if not instruction.rbp_replace:
                                    instruction.instrument_rbp_start(
                                        "\tpushq %{0}\n\tmovq -0x8(%rbp), %{0}".format(rbp_reg))
                                    instruction.instrument_rbp_end(
                                        "\tmovq %{0}, -0x8(%rbp)\n\tpopq %{0}".format(rbp_reg))
                                    instruction.rbp_replace = True
                            elif "(%rsp)" in operand:  # 涉及以栈顶访问，此时由于进行了push操作，需要修改访问位置
                                loc_str = operand[:operand.find("(%rsp)")]
                                loc = int(loc_str, 16) + 8
                                instruction.op_str = instruction.op_str.replace(loc_str + "(%rsp)", hex(loc) + "(%rsp)")

                    if is_assgin(instruction.mnemonic):  # 赋值语句
                        self.handle_assignment(this_idx, fn, memory_exp_addrs, reg_read_addrs, reg_exp_addrs)

                    elif is_call(instruction.mnemonic):  # 函数调用
                        self.handle_call(this_idx, bb_interval, fn, memory_exp_addrs, reg_exp_addrs,
                                         to_use_regs_exp_addr, jmp_from_idxs)

                    elif is_jmp(instruction.mnemonic):  # 跳转指令
                        c_idx, is_remove = self.handle_comparison(this_idx, fn, memory_exp_addrs, reg_read_addrs,
                                                                  reg_exp_addrs, idx_pc_exp_map)

                        if is_remove:
                            instructions_remove.append(fn.cache[c_idx])
                            instructions_remove.append(instruction)

                    else:
                        is_remove = self.handle_operation(this_idx, fn, memory_exp_addrs, reg_read_addrs, reg_exp_addrs)
                        if is_remove:
                            instructions_remove.append(instruction)

                    # 记录各条指令的rax对应表达式地址，便于后续set_ret_exp
                    instruction.rax_exp_addr = reg_exp_addrs["rax"] if "rax" in reg_exp_addrs.keys() else None

                    if has_reg(instruction.op_str[-3:], "rax"):
                        if instruction.mnemonic.startswith("set"):
                            instruction.ret_mne = "b"
                        else:
                            instruction.ret_mne = instruction.mnemonic[-1]

                    else:
                        instruction.ret_mne = fn.cache[idx - 1].ret_mne

                if idx_end is not None:
                    # self.handle_ret_exp(idx_end, hex(fn.cache[l_idx].address)[2:], fn)
                    idxs_end.add(idx_end)

                if r_idx > 0:
                    end_instruction = fn.cache[r_idx - 1]
                    if has_retq and is_only_jmp(end_instruction.mnemonic) \
                            and (".L" not in end_instruction.op_str
                                 or ".L" in end_instruction.op_str
                                 and (int(end_instruction.op_str[2:], 16) < addr
                                      or int(end_instruction.op_str[2:], 16) > fn.cache[-1].address)):
                        # 当存在ret指令，但同时存在跳转到其他函数的指令时，在跳转前需恢复栈，因为跳转不会再返回
                        idxs_end.add(r_idx - 1)

                    # 保存该基本块生成的表达式
                    self.save_to_use_reg_infos(r_idx, fn, to_use_regs_exp_addr, jmp_from_idxs, reg_exp_addrs)

            # 处理基本块入口
            self.add_sym_basic_block(fn, idxs_bb)
            self.add_sym_path_constraint(fn, idx_pc_exp_map, jmp_labels)

            # 自处理的栈按16字节对齐
            if self.stack_size % 16 != 0:
                self.stack_size += 8

            # 处理开始
            print(idx_start)
            if self.use_rbp == 0 and idxs_end:  # 不使用rbp的情况，添加所需内存的运算
                # 伪造rbp，当前函数真实的rbp值在-8(%rbp)处
                # if len(call_graph[addr]) == 0:
                #     rbp_destroy = "\tpushq %rbp\n\tmovq %rsp, %rbp\n\tpushq $0x0\n\tsubq ${}, %rsp"
                # else:
                rbp_destroy = "\tpushq %rbp\n\tmovq %rsp, %rbp\n\tpushq $0x0\n\tsubq ${}, %rsp"
                fn.cache[0].instrument_rbp_start(rbp_destroy.format(hex(self.stack_size)), order=0)

                idx_start = 0

            elif self.use_rbp == 1 and idx_start is not None:  # 使用rbp的情况，替换栈运算值
                instruction_start = fn.cache[idx_start]
                instruction_start_after = fn.cache[idx_start + 1]

                if instruction_start.mnemonic.startswith("sub"):
                    fn.cache[idx_start].op_str = instruction_start.op_str.replace(
                        instruction_start.op_str[1:instruction_start.op_str.find(",")], hex(self.stack_size))
                elif instruction_start_after.mnemonic.startswith("subq") \
                        and "%rsp" in instruction_start_after.op_str[-4:]:
                    fn.cache[idx_start + 1].op_str = instruction_start_after.op_str.replace(
                        instruction_start_after.op_str[1:instruction_start_after.op_str.find(",")],
                        hex(self.stack_size))
                    idx_start = idx_start + 1
                else:
                    instruction_start.instrument_after("\tsubq ${}, %rsp".format(hex(self.stack_size)), 0)

            self.init_to_use_reg_infos(idx_start, fn, to_use_regs_exp_addr)

            # 处理结束
            print(idxs_end)
            for idx_end in idxs_end:
                instruction_end = fn.cache[idx_end]
                print(instruction_end)
                if self.use_rbp == 0:  # 不使用rbp的情况，retq前恢复rbp和rsp值
                    # if len(call_graph[addr]) == 0:
                    #     rbp_recovery = "\taddq ${}, %rsp\n\tpopq %rbp\n\tpopq %rbp"
                    # else:
                    rbp_recovery = "\taddq ${}, %rsp\n\tpopq %rbp\n\tpopq %rbp"
                    instruction_end.instrument_before(rbp_recovery.format(hex(self.stack_size)))

                else:  # 使用rbp的情况，替换栈运算值
                    instruction_end_before = fn.cache[idx_end - 1]

                    if instruction_end.mnemonic.startswith("addq") and "%rsp" in instruction_end.op_str[-4:]:
                        fn.cache[idx_end].op_str = instruction_end.op_str.replace(
                            instruction_end.op_str[1:instruction_end.op_str.find(",")], hex(self.stack_size))
                    elif instruction_end_before.mnemonic.startswith("addq") and "%rsp" in instruction_end_before.op_str[
                                                                                          -4:]:
                        fn.cache[idx_end - 1].op_str = instruction_end_before.op_str.replace(
                            instruction_end_before.op_str[1:instruction_end_before.op_str.find(",")],
                            hex(self.stack_size))
                    else:
                        instruction_end.instrument_before("\taddq ${}, %rsp".format(hex(self.stack_size)))

            # 处理待删除的指令
            for ins_rm in instructions_remove:
                self.replace_nop(ins_rm)

            self.instrument_orders.clear()
            self.stack_size = None

    def instrument_init_array(self):
        # 初始化
        section = self.rewriter.container.sections[".init_array"]
        constructor = DataCell.instrumented(".quad {}".format(sp.SYM_INIT_FN),
                                            8)
        section.cache.append(constructor)

        initfn = Function(sp.SYM_INIT_FN, SYM_INIT_LOC, 0, "")
        initfn.set_instrumented()
        initcode = InstrumentedInstruction(
            '\n'.join(sp.SYM_MODULE_INIT), None, None)

        initfn.cache.append(initcode)
        self.rewriter.container.add_function(initfn)

    def do_instrument(self):
        self.add_symbolic_instrumentation()
        self.instrument_init_array()
