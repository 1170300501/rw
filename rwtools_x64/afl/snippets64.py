# trampoline
AFL_TRAMPOLINE = [
    "\tleaq -(128+24)(%rsp), %rsp",
    "\tmovq %rdx,  0(%rsp)",
    "\tmovq %rcx,  8(%rsp)",
    "\tmovq %rax, 16(%rsp)",
    "\tmovq ${bb_order}, %rcx",
    "\tcall __afl_maybe_log",
    "\tmovq 16(%rsp), %rax",
    "\tmovq  8(%rsp), %rcx",
    "\tmovq  0(%rsp), %rdx",
    "\tleaq (128+24)(%rsp), %rsp"
]

# __afl_maybe_log
AFL_MAYBE_LOG = [
    "\tlahf",
    "\tseto %al",
    "\tmovq __afl_area_ptr(%rip), %rdx",
    "\ttestq %rdx, %rdx",
    "\tje __afl_setup"
]

# __afl_store
AFL_STORE = [
    # 0: coverage_only
    # 1: skip_counts
]

AFL_STORE_COVERAGE_ONLY = [
    "\txorq __afl_prev_loc(%rip), %rcx",
    "\txorq %rcx, __afl_prev_loc(%rip)",
    "\tshrq $1, __afl_prev_loc(%rip)"
]

AFL_STORE_NOT_COVERAGE_ONLY = []

AFL_STORE_SKIP_COUNTS = [
    "\torb $1, (%rdx, %rcx, 1)"
]

AFL_STORE_NOT_SKIP_COUNTS = [
    "\tincb (%rdx, %rcx, 1)"
]

# __afl_return
AFL_RETURN = [
    "\taddb $127, %al",
    "\tsahf",
    "\tret"
]

# __afl_setup
AFL_SETUP = [
    "\tcmpb $0, __afl_setup_failure(%rip)",
    "\tjne __afl_return",
    # 2: apple
    "\ttestq %rdx, %rdx",
    "\tje __afl_setup_first",
    "\tmovq %rdx, __afl_area_ptr(%rip)",
    "\tjmp __afl_store"
]

AFL_SETUP_APPLE = [
    "\tmovq __afl_global_area_ptr@GOTPCREL(%rip), %rdx"
    "\tmovq (%rdx), %rdx"
]

AFL_SETUP_NOT_APPLE = [
    "\tmovq  __afl_global_area_ptr(%rip), %rdx"
]

# __afl_setup_first
AFL_SETUP_FIRST = [
    "\tleaq -352(%rsp), %rsp",
    "\tmovq %rax,   0(%rsp)",
    "\tmovq %rcx,   8(%rsp)",
    "\tmovq %rdi,  16(%rsp)",
    "\tmovq %rsi,  32(%rsp)",
    "\tmovq %r8,   40(%rsp)",
    "\tmovq %r9,   48(%rsp)",
    "\tmovq %r10,  56(%rsp)",
    "\tmovq %r11,  64(%rsp)",
    "\tmovq %xmm0,  96(%rsp)",
    "\tmovq %xmm1,  112(%rsp)",
    "\tmovq %xmm2,  128(%rsp)",
    "\tmovq %xmm3,  144(%rsp)",
    "\tmovq %xmm4,  160(%rsp)",
    "\tmovq %xmm5,  176(%rsp)",
    "\tmovq %xmm6,  192(%rsp)",
    "\tmovq %xmm7,  208(%rsp)",
    "\tmovq %xmm8,  224(%rsp)",
    "\tmovq %xmm9,  240(%rsp)",
    "\tmovq %xmm10, 256(%rsp)",
    "\tmovq %xmm11, 272(%rsp)",
    "\tmovq %xmm12, 288(%rsp)",
    "\tmovq %xmm13, 304(%rsp)",
    "\tmovq %xmm14, 320(%rsp)",
    "\tmovq %xmm15, 336(%rsp)",
    "\tpushq %r12",
    "\tmovq  %rsp, %r12",
    "\tsubq  $16, %rsp",
    "\tandq  $0xfffffffffffffff0, %rsp",
    "\tleaq .AFL_SHM_ENV(%rip), %rdi",
    "\tcall getenv@plt",
    "\ttestq %rax, %rax",
    "\tje    __afl_setup_abort",
    "\tmovq  %rax, %rdi",
    "\tcall atoi@plt",
    "\txorq %rdx, %rdx   /* shmat flags    */",
    "\txorq %rsi, %rsi   /* requested addr */",
    "\tmovq %rax, %rdi   /* SHM ID         */",
    "\tcall shmat@plt",
    "\tcmpq $-1, %rax",
    "\tje   __afl_setup_abort",
    "\tmovq %rax, %rdx",
    "\tmovq %rax, __afl_area_ptr(%rip)",
    # -2: apple
    "\tmovq %rax, %rdx"
]

AFL_SETUP_FIRST_APPLE = [
    "\tmovq %rax, __afl_global_area_ptr(%rip)"
]

AFL_SETUP_FIRST_NOT_APPLE = [
    "\tmovq __afl_global_area_ptr@GOTPCREL(%rip), %rdx",
    "\tmovq %rax, (%rdx)"
]

# __afl_forkserver
AFL_FORK_SERVER = [
    "\tpushq %rdx",
    "\tpushq %rdx",
    "\tmovq $4, %rdx               /* length    */",
    "\tleaq __afl_temp(%rip), %rsi /* data      */",
    "\tmovq $199, %rdi         /* file desc */",
    "\tcall write@plt",
    "\tcmpq $4, %rax",
    "\tjne  __afl_fork_resume"
]

# __afl_fork_wait_loop
AFL_FORK_WAIT_LOOP = [
    "\tmovq $4, %rdx               /* length    */",
    "\tleaq __afl_temp(%rip), %rsi /* data      */",
    "\tmovq $198, %rdi         /* file desc */",
    "\tcall read@plt",
    "\tcmpq $4, %rax",
    "\tjne  __afl_die",
    "\tcall fork@plt",
    "\tcmpq $0, %rax",
    "\tjl   __afl_die",
    "\tje   __afl_fork_resume",
    "\tmovl %eax, __afl_fork_pid(%rip)",
    "\tmovq $4, %rdx                   /* length    */",
    "\tleaq __afl_fork_pid(%rip), %rsi /* data      */",
    "\tmovq $199, %rdi         /* file desc */",
    "\tcall write@plt",
    "\tmovq $0, %rdx                   /* no flags  */\n",
    "\tleaq __afl_temp(%rip), %rsi     /* status    */\n",
    "\tmovq __afl_fork_pid(%rip), %rdi /* PID       */\n",
    "\tcall waitpid@plt",
    "\tcmpq $0, %rax",
    "\tjle  __afl_die",
    "\tmovq $4, %rdx               /* length    */\n"
    "\tleaq __afl_temp(%rip), %rsi /* data      */\n"
    "\tmovq $199, %rdi         /* file desc */",
    "\tcall write@plt",
    "\tjmp  __afl_fork_wait_loop"
]

# __afl_fork_resume
AFL_FORK_RESUME = [
    "\tmovq $198, %rdi",
    "\tcall close@plt",
    "\tmovq $199, %rdi",
    "\tcall close@plt",
    "\tpopq %rdx",
    "\tpopq %rdx",
    "\tmovq %r12, %rsp",
    "\tpopq %r12",
    "\tmovq  0(%rsp), %rax",
    "\tmovq  8(%rsp), %rcx",
    "\tmovq 16(%rsp), %rdi",
    "\tmovq 32(%rsp), %rsi",
    "\tmovq 40(%rsp), %r8",
    "\tmovq 48(%rsp), %r9",
    "\tmovq 56(%rsp), %r10",
    "\tmovq 64(%rsp), %r11",
    "\tmovq  96(%rsp), %xmm0",
    "\tmovq 112(%rsp), %xmm1",
    "\tmovq 128(%rsp), %xmm2",
    "\tmovq 144(%rsp), %xmm3",
    "\tmovq 160(%rsp), %xmm4",
    "\tmovq 176(%rsp), %xmm5",
    "\tmovq 192(%rsp), %xmm6",
    "\tmovq 208(%rsp), %xmm7",
    "\tmovq 224(%rsp), %xmm8",
    "\tmovq 240(%rsp), %xmm9",
    "\tmovq 256(%rsp), %xmm10",
    "\tmovq 272(%rsp), %xmm11",
    "\tmovq 288(%rsp), %xmm12",
    "\tmovq 304(%rsp), %xmm13",
    "\tmovq 320(%rsp), %xmm14",
    "\tmovq 336(%rsp), %xmm15",
    "\tleaq 352(%rsp), %rsp",
    "\tjmp  __afl_store"
]

# __afl_die
AFL_DIE = [
    "\txorq %rax, %rax",
    "\tcall _exit@plt"
]

# __afl_setup_abort
AFL_SETUP_ABORT = [
    "\tincb __afl_setup_failure(%rip)",
    "\tmovq %r12, %rsp",
    "\tpopq %r12",
    "\tmovq  0(%rsp), %rax",
    "\tmovq  8(%rsp), %rcx",
    "\tmovq 16(%rsp), %rdi",
    "\tmovq 32(%rsp), %rsi",
    "\tmovq 40(%rsp), %r8",
    "\tmovq 48(%rsp), %r9",
    "\tmovq 56(%rsp), %r10",
    "\tmovq 64(%rsp), %r11",
    "\tmovq  96(%rsp), %xmm0",
    "\tmovq 112(%rsp), %xmm1",
    "\tmovq 128(%rsp), %xmm2",
    "\tmovq 144(%rsp), %xmm3",
    "\tmovq 160(%rsp), %xmm4",
    "\tmovq 176(%rsp), %xmm5",
    "\tmovq 192(%rsp), %xmm6",
    "\tmovq 208(%rsp), %xmm7",
    "\tmovq 224(%rsp), %xmm8",
    "\tmovq 240(%rsp), %xmm9",
    "\tmovq 256(%rsp), %xmm10",
    "\tmovq 272(%rsp), %xmm11",
    "\tmovq 288(%rsp), %xmm12",
    "\tmovq 304(%rsp), %xmm13",
    "\tmovq 320(%rsp), %xmm14",
    "\tmovq 336(%rsp), %xmm15",
    "\tleaq 352(%rsp), %rsp",
    "\tjmp __afl_return"
]

AFL_VAR = [
    # 0: apple
    "\t.comm    __afl_global_area_ptr, 8, 8"
]

AFL_VAR_APPLE = [
    "\t.comm   __afl_area_ptr, 8",
    # 1: coverage only
    "\t.comm   __afl_fork_pid, 4",
    "\t.comm   __afl_temp, 4",
    "\t.comm   __afl_setup_failure, 1"
]

AFL_VAR_APPLE_COVERAGE_ONLY = [
    "\t.comm   __afl_prev_loc, 8"
]

AFL_VAR_APPLE_NOT_COVERAGE_ONLY = [
]

AFL_VAR_NOT_APPLE = [
    "\t.lcomm   __afl_area_ptr, 8",
    # 1: coverage only
    "\t.lcomm   __afl_fork_pid, 4",
    "\t.lcomm   __afl_temp, 4",
    "\t.lcomm   __afl_setup_failure, 1"
]

AFL_VAR_NOT_APPLE_COVERAGE_ONLY = [
    "\t.lcomm   __afl_prev_loc, 8"
]

AFL_VAR_NOT_APPLE_NOT_COVERAGE_ONLY = [
]

AFL_SHM_ENV = [
    "\t.asciz \"__AFL_SHM_ID\""
]