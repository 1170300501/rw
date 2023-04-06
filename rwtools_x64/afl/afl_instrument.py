import random as r
import copy
import time
import os

from librw_x64.container import Function, InstrumentedInstruction
from rwtools_x64.utils import *

import sys
if sys.maxsize > 2 ** 32:
    from . import snippets64 as sp
else:
    from . import snippets32 as sp

t = time.time()
r.seed(int(t) ^ int(round((t - int(t)) * 1000000)) ^ os.getpid())

MAP_SIZE = 2 ** 16

AFL_MAYBE_LOG_LOC = 0x1100000000000000
AFL_STORE_LOC = 0x1200000000000000
AFL_RETURN_LOC = 0x1300000000000000
AFL_SETUP_LOC = 0x1400000000000000
AFL_SETUP_FIRST_LOC = 0x1500000000000000
AFL_FORKSERVER_LOC = 0x1600000000000000
AFL_FORK_WAIT_LOOP_LOC = 0x1700000000000000
AFL_FORK_RESUME_LOC = 0x1800000000000000
AFL_DIE_LOC = 0x1900000000000000
AFL_SETUP_ABORT_LOC = 0x1a00000000000000
AFL_VAR_LOC = 0x1b00000000000000
AFL_SHM_ENV_LOC = 0x1c00000000000000


class AFL_Instrument:
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

    def get_basic_block_afl_info(self, pre_idxs_bb):
        basic_blocks_bits = dict()
        if not pre_idxs_bb:
            return

        for idx in pre_idxs_bb:
            bb_bits = r.randint(1, MAP_SIZE)
            basic_blocks_bits[idx] = bb_bits
            #print(idx, bb_bits)

        return basic_blocks_bits

    def add_afl_trampoline_instrumentation(self, fn, idxs_bb, bb_bits):
        if not idxs_bb:
            return

        # 第一个基本块必须插桩
        if idxs_bb[0] == len(fn.cache):
            return 

        fn.cache[idxs_bb[0]].instrument_before("\n".join(sp.AFL_TRAMPOLINE).format(
            bb_order="0x%08x" % bb_bits[idxs_bb[0]]
        ), 0)

        for idx in idxs_bb[1:]:
            if idx == len(fn.cache):
                continue

            if r.randint(0, 100) < self.inst_ratio:  # 按概率插桩
                fn.cache[idx].instrument_before("\n".join(sp.AFL_TRAMPOLINE).format(
                    bb_order="0x%08x" % bb_bits[idx]
                ), 0)

    def add_instrumented_function(self, fn_name, fn_loc, fn_code):
        fn = Function(fn_name, fn_loc, 0, "")
        fn.set_instrumented()
        code = InstrumentedInstruction('\n'.join(fn_code), None, None)
        fn.cache.append(code)
        self.rewriter.container.add_function(fn)

    def add_afl_text_instrumentation(self):
        self.add_instrumented_function("__afl_maybe_log", AFL_MAYBE_LOG_LOC, sp.AFL_MAYBE_LOG)

        sp.AFL_STORE.clear()
        sp.AFL_STORE.extend(sp.AFL_STORE_COVERAGE_ONLY if self.coverage_only
                            else sp.AFL_STORE_NOT_COVERAGE_ONLY)
        sp.AFL_STORE.extend(sp.AFL_STORE_NOT_SKIP_COUNTS if self.skip_counts == 0
                            else sp.AFL_STORE_SKIP_COUNTS)
        self.add_instrumented_function("__afl_store", AFL_STORE_LOC, sp.AFL_STORE)

        self.add_instrumented_function("__afl_return", AFL_RETURN_LOC, sp.AFL_RETURN)

        setup_instrumentation = copy.deepcopy(sp.AFL_SETUP[:2])
        setup_instrumentation.extend(sp.AFL_SETUP_NOT_APPLE if not self.apple
                                     else sp.AFL_SETUP_APPLE)
        setup_instrumentation.extend(sp.AFL_SETUP[2:])
        self.add_instrumented_function("__afl_setup", AFL_SETUP_LOC, setup_instrumentation)

        setup_first_instrumentation = copy.deepcopy(sp.AFL_SETUP_FIRST[:-2])
        setup_first_instrumentation.extend(sp.AFL_SETUP_FIRST_NOT_APPLE if not self.apple
                                           else sp.AFL_SETUP_FIRST_APPLE)
        setup_first_instrumentation.extend(sp.AFL_SETUP_FIRST[-2:])
        self.add_instrumented_function("__afl_setup_first", AFL_SETUP_FIRST_LOC, setup_first_instrumentation)

        self.add_instrumented_function("__afl_forkserver", AFL_FORKSERVER_LOC, sp.AFL_FORK_SERVER)

        self.add_instrumented_function("__afl_fork_wait_loop", AFL_FORK_WAIT_LOOP_LOC, sp.AFL_FORK_WAIT_LOOP)

        self.add_instrumented_function("__afl_fork_resume", AFL_FORK_RESUME_LOC, sp.AFL_FORK_RESUME)

        self.add_instrumented_function("__afl_die", AFL_DIE_LOC, sp.AFL_DIE)

        self.add_instrumented_function("__afl_setup_abort", AFL_SETUP_ABORT_LOC, sp.AFL_SETUP_ABORT)

        var_if_apple = sp.AFL_VAR_NOT_APPLE if not self.apple else sp.AFL_VAR_APPLE
        var_if_coverage_only = sp.AFL_VAR_NOT_APPLE_COVERAGE_ONLY if not self.apple and self.coverage_only \
            else sp.AFL_VAR_NOT_APPLE_NOT_COVERAGE_ONLY if not self.apple and not self.coverage_only \
            else sp.AFL_VAR_APPLE_COVERAGE_ONLY if self.apple and self.coverage_only \
            else sp.AFL_VAR_APPLE_NOT_COVERAGE_ONLY
        var_instrumentation = copy.deepcopy(var_if_apple[:1])
        var_instrumentation.extend(var_if_coverage_only)
        var_instrumentation.extend(var_if_apple[1:])
        var_instrumentation.extend(sp.AFL_VAR)
        self.add_instrumented_function(".AFL_VAR", AFL_VAR_LOC, var_instrumentation)

        self.add_instrumented_function(".AFL_SHM_ENV", AFL_SHM_ENV_LOC, sp.AFL_SHM_ENV)

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
        visited_blocks.add(block_bits)
        if len(self.blocks_children[block_bits]) != 0:
            blocks_children_list = list(self.blocks_children[block_bits])
            for child in blocks_children_list:
                if child not in visited_blocks:
                    self.dfs(child, visited_blocks)
                else:
                    self.blocks_children[block_bits].remove(child)

            self.blocks_children[block_bits] = set(blocks_children_list)

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

    def do_instrument(self):
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
            bb_bits = self.get_basic_block_afl_info(idxs_bb)
            # print(bb_bits)

            self.taint_spread(addr_to_handle, fn_to_handle, bb_intervals, start_idx, bb_bits, jmp_from_idxs)
            self.add_afl_trampoline_instrumentation(fn_to_handle, list(idxs_bb), bb_bits)

            # print(self.blocks_children)
            if start_idx is not None and start_bits is None:
                start_bits = bb_bits[start_idx]

            call_graph.pop(addr_to_handle)
            visited_functions.add(addr_to_handle)

        self.dfs(start_bits, set())
        self.dump_taint_counts()
        self.dump_blocks_children()
        self.add_afl_text_instrumentation()

    # def do_instrument(self):
    #     for addr, fn in self.rewriter.container.functions.items():
    #         idxs_bb = set()
    #         jmp_labels = dict()
    #
    #         for idx, instruction in enumerate(fn.cache):
    #
    #             if isinstance(instruction, InstrumentedInstruction):
    #                 continue
    #
    #             if instruction.mnemonic.startswith("push") and instruction.op_str == "%rbp":
    #                 # push rbp
    #                 if not idxs_bb:
    #                     idxs_bb.add(idx + 1)
    #
    #             elif instruction.mnemonic.startswith("j"):  # 跳转指令
    #                 idxs_bb.add(idx + 1)
    #                 jmp_labels[idx] = instruction.op_str
    #
    #         merge_basic_block_infos(fn, idxs_bb, jmp_labels)
    #         self.add_afl_trampoline_instrumentation(fn, list(idxs_bb))
    #
    #     self.add_afl_text_instrumentation()