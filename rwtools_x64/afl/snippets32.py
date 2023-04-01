AFL_TRAMPOLINE = [
    "\tmovl $0x%08x, $ecx",
    "\tcall __afl_maybe_log",
]

AFL_MAYBE_LOG = [
    "\tlahf",
    "\tseto %al",
    "\tmovl __afl_area_ptr, %edx",
    "\ttestl %edx, %edx",
    "\tje __afl_setup"
]

AFL_STORE = [

]

AFL_RETURN = [
    "\taddb $127, %al",
    "\tsahf",
    "\tret",
]

AFL_SET_UP = [
    "\tcmpb $0, __afl_setup_failure",
    "\tjne __afl_return",

]