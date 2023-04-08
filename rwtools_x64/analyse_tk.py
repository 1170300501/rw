import random as r
import copy
from collections import deque

from librw_x64.container import Function, InstrumentedInstruction
from rwtools_x64.utils import *


class Taint_Analyser:
    def __init__(self, rewriter, coverage_only=True, skip_counts=0, apple=False):
        self.rewriter = rewriter

        self.inst_ratio = 100  # 插桩率
        self.coverage_only = coverage_only
        self.skip_counts = skip_counts
        self.apple = apple

        # self.call_taint_inputs = dict()
        self.call_bb_taint_counts = dict()
        self.next_bits_from_call_ret = dict()  # block_bits_has_call -> [fn_addr_of_block, next_bits_of_block...]

        self.call_graph = dict()          # caller_addr -> callee_addr_str
        self.reverse_call_graph = dict()  # callee_addr -> caller_addr -> is_call
        self.blocks_calls = dict()        # block_bits -> call_addr
        self.blocks_children = dict()

    def get_basic_block_afl_info(self, pre_idxs_bb, fn):
        basic_blocks_bits = dict()
        if not pre_idxs_bb:
            return

        for i in range(len(pre_idxs_bb) - 1):
            l_idx, r_idx = pre_idxs_bb[i], pre_idxs_bb[i+1]
            for t_idx in range(l_idx, min(l_idx + 11, r_idx)):
                inst = fn.cache[t_idx]
                if inst.mnemonic.startswith("call") and inst.op_str == "__afl_maybe_log":
                    basic_blocks_bits[l_idx] = int(handle_get_operands(fn.cache[t_idx-1].op_str)[0][1:], 16)
                    break

        return basic_blocks_bits

    def get_call_graph(self):
        for addr, fn in self.rewriter.container.functions.items():
            end_addr = fn.cache[-1].address if len(fn.cache) > 0 else -1
            if addr not in self.call_graph.keys():
                self.call_graph[addr] = list()

            for idx, instruction in enumerate(fn.cache):
                if (is_call(instruction.mnemonic) or is_only_jmp(instruction.mnemonic)) \
                        and (instruction.op_str.find("@plt") != -1 or instruction.op_str.startswith(".L")):

                    callee_addr_str = instruction.op_str
                    if callee_addr_str.startswith(".L"):
                        callee_addr_str = callee_addr_str[2:]
                        callee_addr = int(instruction.op_str[2:], 16)
                        if addr < callee_addr < end_addr:
                            continue

                        if callee_addr not in self.reverse_call_graph.keys():
                            self.reverse_call_graph[callee_addr] = dict()

                        self.reverse_call_graph[callee_addr][addr] = is_call(instruction.mnemonic)

                    # 用于记录调用情况
                    self.call_graph[addr].append(callee_addr_str)

        # print(self.call_graph)
        # print(self.reverse_call_graph)

    def taint_spread(self, addr, fn, bb_intervals, start_idx, basic_blocks_bits, jmp_from_idxs):
        if len(bb_intervals) == 0:
            return

        self.call_bb_taint_counts[addr] = dict()
        taint_mmrs = set()
        taint_regs = {k: list() for k, _ in bb_intervals.values()}

        bb_queue = [bb_intervals[start_idx]]
        changed = dict()
        visited_intervals = set()

        use_not_define_regs = get_use_not_define_regs(fn, bb_intervals.values())

        def has_taint(t_op):
            t_flag = False
            if get_op_type(t_op) == "r" and not has_segment_reg(t_op) and regindex[t_op[1:]][0] in taint_regs[l_idx]:
                t_flag = True
            elif get_op_type(t_op) == "m":
                if t_op in taint_mmrs:
                    t_flag = True
                else:
                    for t_reg in taint_regs[l_idx]:
                        if has_reg(t_op, t_reg) != "":
                            t_flag = True
                            break

            return t_flag

        def spread(s_op, t_flag):
            # 污点传播
            if t_flag:
                if get_op_type(s_op) == "r" and not has_reg(s_op, "rsp") and not has_segment_reg(s_op) and regindex[s_op[1:]][0] not in taint_regs[l_idx]:
                    taint_regs[l_idx].append(regindex[s_op[1:]][0])
                elif get_op_type(s_op) == "m":
                    taint_mmrs.add(s_op)

            # 无污点传播的情况下，原污点被清除
            else:
                if get_op_type(s_op) == "r" and not has_segment_reg(s_op) and regindex[s_op[1:]][0] in taint_regs[l_idx]:
                    taint_regs[l_idx].remove(regindex[s_op[1:]][0])
                elif s_op in taint_mmrs:
                    taint_mmrs.remove(s_op)

        def find_ret_edge(cur_callee_addr):
            # 将调用加入基本块的子节点列表
            for b_bits, block_callee_addr in self.blocks_calls.items():
                if cur_callee_addr == block_callee_addr:
                    # 找到调用者基本块的后续标签
                    next_bits_list = self.next_bits_from_call_ret[b_bits]
                    caller_fn_start_addr = next_bits_list[0]

                    if not self.reverse_call_graph[cur_callee_addr][caller_fn_start_addr]:
                        # 调用方式是jmp，则继续倒退寻找上一层caller
                        find_ret_edge(caller_fn_start_addr)

                    else:
                        for next_bits in next_bits_list[1:]:
                            self.blocks_children[block_bits].add(next_bits)

        while len(bb_queue) > 0:
            bb_interval = bb_queue.pop(0)
            l_idx, r_idx = bb_interval
            # print(fn.cache[l_idx])

            if bb_interval in visited_intervals and not changed[l_idx]:
                continue

            visited_intervals.add(bb_interval)

            block_bits = basic_blocks_bits[l_idx]

            if block_bits not in self.call_bb_taint_counts.values():
                self.call_bb_taint_counts[addr][block_bits] = 0

            if block_bits not in self.blocks_children.keys():
                self.blocks_children[block_bits] = set()

            block_taint = False
            has_call = False

            if l_idx == start_idx:
                taint_regs[l_idx].extend(use_not_define_regs[l_idx])
                taint_regs[l_idx] = list(set(taint_regs[l_idx]))
            # print(taint_regs[l_idx])

            for idx, instruction in enumerate(fn.cache[l_idx:r_idx]):
                # print(idx + l_idx, instruction)
                ops = handle_get_operands(instruction.op_str)
                taint_flag = False

                # 赋值
                if is_assgin(instruction.mnemonic):
                    taint_flag = has_taint(ops[0])
                    spread(ops[1], taint_flag)

                    if taint_flag and "(" in instruction.op_str and len(instruction.op_str.split(",")) == 2:
                        # 涉及内存，而不是编译器优化的运算
                        self.call_bb_taint_counts[addr][block_bits] += 1

                # 运算
                elif is_operation(instruction.mnemonic):
                    if not instruction.mnemonic.startswith("test") and not instruction.mnemonic.startswith("cmp"):
                        ops = ops[:-1] if len(ops) == 3 else ops
                        for op in ops:
                            taint_flag = taint_flag or has_taint(op)

                        if len(ops) > 1:
                            spread(ops[-1], taint_flag)
                        elif not instruction.mnemonic.startswith("neg") \
                                and not instruction.mnemonic.startswith("not"):
                            spread("%rax", taint_flag)

                        if taint_flag:
                            score = 5 if "div" in instruction.mnemonic else 1  # 除零错误的严重性
                            self.call_bb_taint_counts[addr][block_bits] += score

                # 调用
                elif (is_call(instruction.mnemonic) or is_only_jmp(instruction.mnemonic)) \
                        and instruction.op_str.startswith(".L"):
                    callee_addr = int(instruction.op_str[2:], 16)
                    if fn.cache[0].address < callee_addr < fn.cache[-1].address:
                        continue

                    # if call_addr not in self.call_taint_inputs.keys():
                    #     self.call_taint_inputs[call_addr] = list()

                    for p_reg in param_regs:
                        if p_reg in taint_regs[l_idx]:
                            taint_flag = True
                            # self.call_taint_inputs[call_addr].append(p_reg)
                    # 假设rax与污点有关
                    spread("%rax", taint_flag)
                    self.blocks_calls[block_bits] = callee_addr

                    has_call = True

                # 其他情况
                elif len(ops) > 0 and not is_nop(instruction.mnemonic):
                    spread(ops[-1], False)

                if taint_flag:
                    block_taint = True

            if block_taint:
                self.call_bb_taint_counts[addr][block_bits] += 1

            if fn.cache[r_idx - 1].mnemonic.startswith("retq"):

                # 将调用加入基本块的子节点列表
                for bits, c_addr in self.blocks_calls.items():
                    if addr == c_addr:
                        self.blocks_children[bits].add(basic_blocks_bits[start_idx])

                # find_ret_edge(addr)

            self.next_bits_from_call_ret[block_bits] = list()
            self.next_bits_from_call_ret[block_bits].append(addr)

            # 后续直接复制污点情况
            if r_idx != len(fn.cache) and not is_ret(fn.cache[r_idx-1].mnemonic) \
                    and not is_only_jmp(fn.cache[r_idx-1].mnemonic):
                tmp_taint_regs = copy.deepcopy(taint_regs[r_idx])
                taint_regs[r_idx].extend(taint_regs[l_idx])
                taint_regs[r_idx] = list(set(taint_regs[r_idx]))

                changed[r_idx] = len(set(taint_regs[r_idx]) - set(tmp_taint_regs)) != 0
                bb_queue.append(bb_intervals[r_idx])

                self.blocks_children[block_bits].add(basic_blocks_bits[r_idx])

                if has_call:
                    self.next_bits_from_call_ret[block_bits].append(basic_blocks_bits[r_idx])

            # 跳转块复制污点情况
            for j_idx, from_idxs in jmp_from_idxs.items():
                if r_idx - 1 in from_idxs:
                    tmp_taint_regs = copy.deepcopy(taint_regs[j_idx])
                    taint_regs[j_idx].extend(taint_regs[l_idx])
                    taint_regs[j_idx] = list(set(taint_regs[j_idx]))

                    changed[j_idx] = len(set(taint_regs[j_idx]) - set(tmp_taint_regs)) != 0
                    bb_queue.append(bb_intervals[j_idx])

                    self.blocks_children[block_bits].add(basic_blocks_bits[j_idx])

                    if has_call:
                        self.next_bits_from_call_ret[block_bits].append(basic_blocks_bits[j_idx])

                    break

    def dfs(self, block_bits, visited_blocks):
        # 通过dfs删除多余的边
        stack = deque()
        visited_blocks = set()
        stack.appendleft(block_bits)

        while len(stack) > 0:
            block_bits = stack.popleft()
            visited_blocks.add(block_bits)
            
            if len(self.blocks_children[block_bits]) != 0:
                blocks_children_list = list(self.blocks_children[block_bits])
                for child in blocks_children_list:
                    if child not in visited_blocks:
                        stack.appendleft(child)
                    else:
                        self.blocks_children[block_bits].remove(child)

    def dump_taint_counts(self):
        write_ptrs = list()
        for call_addr, blocks_taint_count in self.call_bb_taint_counts.items():
            write_ptrs.append(self.rewriter.container.functions[call_addr].name)

            for block_bits, block_taint_count in blocks_taint_count.items():
                write_ptrs.append(str(block_bits) + " " + str(block_taint_count))

        with open("taint_count", "w") as f:
            f.write("\n".join(write_ptrs))

    def dump_blocks_children(self):
        write_ptrs = list()
        for bits, block_children in self.blocks_children.items():
            write_ptrs.append(str(bits) + " " + " ".join([str(c) for c in block_children]))

        with open("blocks_children", "w") as f:
            f.write("\n".join(write_ptrs))

    def do_analysis(self):
        self.get_call_graph()
        # print(self.call_graph)
        call_graph = copy.deepcopy(self.call_graph)
        visited_functions = set()
        func_num = len(self.rewriter.container.functions)
        start_bits = None

        while len(visited_functions) != func_num:
            group_to_handle = None
            for addr, fn in self.rewriter.container.functions.items():
                if addr not in visited_functions:
                    for _, calls in call_graph.items():
                        if hex(addr)[2:] not in calls:
                            group_to_handle = (addr, fn)
                            break

            addr_to_handle, fn_to_handle = group_to_handle
            idxs_bb = list()
            jmp_labels = dict()
            print(fn_to_handle.name)

            for idx, instruction in enumerate(fn_to_handle.cache):

                if isinstance(instruction, InstrumentedInstruction):
                    continue

                if idx == 0:
                    idxs_bb.append(0)

                if instruction.mnemonic.startswith("j"):  # 跳转指令
                    idxs_bb.append(idx + 1)

                    if instruction.op_str not in jmp_labels.keys():
                        jmp_labels[instruction.op_str] = list()

                    jmp_labels[instruction.op_str].append(idx)

            jmp_from_idxs = merge_basic_block_infos(fn_to_handle, idxs_bb, jmp_labels)
            bb_intervals, start_idx = get_basic_blocks(idxs_bb, len(fn_to_handle.cache))
            bb_bits = self.get_basic_block_afl_info(idxs_bb, fn)
            # print(bb_bits)

            self.taint_spread(addr_to_handle, fn_to_handle, bb_intervals, start_idx, bb_bits, jmp_from_idxs)

            # print(self.blocks_children)
            if start_idx is not None and start_bits is None:
                start_bits = bb_bits[start_idx]

            call_graph.pop(addr_to_handle)
            visited_functions.add(addr_to_handle)

        self.dfs(start_bits, set())
        self.dump_taint_counts()
        self.dump_blocks_children()
        print("afl instrumentation is finished.")
