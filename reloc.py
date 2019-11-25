
from triton     import TritonContext, ARCH, Instruction, MemoryAccess, CPUSIZE, MODE

import  sys
import os
import string

TARGET = os.path.join(os.path.dirname(__file__), 'a.out')

BASE_PLT   = 0x10000000
BASE_ARGV  = 0x20000000
BASE_ALLOC = 0x30000000
BASE_STACK = 0x9fffffff


def getMemoryString(ctx, addr):
    s = str()
    index = 0

    while ctx.getConcreteMemoryValue(addr+index):
        c = chr(ctx.getConcreteMemoryValue(addr+index))
        if c not in string.printable: c = ""
        s += c
        index  += 1

    return s

def getFormatString(ctx, addr):
    return getMemoryString(ctx, addr)                                               \
           .replace("%s", "{}").replace("%d", "{:d}").replace("%#02x", "{:#02x}")   \
           .replace("%#x", "{:#x}").replace("%x", "{:x}").replace("%02X", "{:02x}") \
           .replace("%c", "{:c}").replace("%02x", "{:02x}").replace("%ld", "{:d}")  \
           .replace("%*s", "").replace("%lX", "{:x}").replace("%08x", "{:08x}")     \
           .replace("%u", "{:d}").replace("%lu", "{:d}")                            \


def hookingHandler(ctx):
    pc = ctx.getConcreteRegisterValue(ctx.registers.rip)
    for rel in customRelocation:
        if rel[2] == pc:
            # Emulate the routine and the return value
            ret_value = rel[1](ctx)
            if ret_value is not None:
                ctx.setConcreteRegisterValue(ctx.registers.rax, ret_value)

            # Get the return address
            ret_addr = ctx.getConcreteMemoryValue(MemoryAccess(ctx.getConcreteRegisterValue(ctx.registers.rsp), CPUSIZE.QWORD))

            # Hijack RIP to skip the call
            ctx.setConcreteRegisterValue(ctx.registers.rip, ret_addr)

            # Restore RSP (simulate the ret)
            ctx.setConcreteRegisterValue(ctx.registers.rsp, ctx.getConcreteRegisterValue(ctx.registers.rsp)+CPUSIZE.QWORD)
    return

def makeRelocation(ctx, binary):
    # Perform our own relocations
    try:
        for rel in binary.pltgot_relocations:
            symbolName = rel.symbol.name
            symbolRelo = rel.address
            for crel in customRelocation:
                if symbolName == crel[0]:
                    ctx.setConcreteMemoryValue(MemoryAccess(symbolRelo, CPUSIZE.QWORD), crel[2])
    except:
        pass

def printfHandler(ctx):

    # Get arguments
    arg1   = getFormatString(ctx, ctx.getConcreteRegisterValue(ctx.registers.rdi))
    arg2   = ctx.getConcreteRegisterValue(ctx.registers.rsi)
    arg3   = ctx.getConcreteRegisterValue(ctx.registers.rdx)
    arg4   = ctx.getConcreteRegisterValue(ctx.registers.rcx)
    arg5   = ctx.getConcreteRegisterValue(ctx.registers.r8)
    arg6   = ctx.getConcreteRegisterValue(ctx.registers.r9)
    nbArgs = arg1.count("{")
    args   = [arg2, arg3, arg4, arg5, arg6][:nbArgs]
    s      = arg1.format(*args)


    # Return value
    return len(s)


# Simulate the putchar() function
def putcharHandler(ctx):

    # Get arguments
    arg1 = ctx.getConcreteRegisterValue(ctx.registers.rdi)
    sys.stdout.write(chr(arg1) + '\n')

    # Return value
    return 2


# Simulate the puts() function
def putsHandler(ctx):

    # Get arguments
    arg1 = getMemoryString(ctx, ctx.getConcreteRegisterValue(ctx.registers.rdi))
    sys.stdout.write(arg1 + '\n')

    # Return value
    return len(arg1) + 1


# Simulate the strncpy() function
def strncpyHandler(ctx):

    dst = ctx.getConcreteRegisterValue(ctx.registers.rdi)
    src = ctx.getConcreteRegisterValue(ctx.registers.rsi)
    cnt = ctx.getConcreteRegisterValue(ctx.registers.rdx)
    for index in range(cnt):
        dmem  = MemoryAccess(dst + index, 1)
        smem  = MemoryAccess(src + index, 1)
        cell = ctx.getMemoryAst(smem)
        expr = ctx.newSymbolicExpression(cell, "strncpy byte")
        ctx.setConcreteMemoryValue(dmem, cell.evaluate())
        ctx.assignSymbolicExpressionToMemory(expr, dmem)

    return dst


def exitHandler(ctx):

    ret = ctx.getConcreteRegisterValue(ctx.registers.rdi)
    ast = ctx.getAstContext()
    pco = ctx.getPathPredicate()
    # Ask for a new model which set all symbolic variables to ascii printable characters
    mod = ctx.getModel(ast.land(
            [pco] +
            [ast.variable(ctx.getSymbolicVariable(0))  == ord('C')] +
            [ast.variable(ctx.getSymbolicVariable(1))  == ord('T')] +
            [ast.variable(ctx.getSymbolicVariable(2))  == ord('F')] +
            [ast.variable(ctx.getSymbolicVariable(3))  == ord('{')] +
            [ast.variable(ctx.getSymbolicVariable(50)) == ord('}')] +
            [ast.variable(ctx.getSymbolicVariable(x))  >= 0x20 for x in range(4, 49)] +
            [ast.variable(ctx.getSymbolicVariable(x))  <= 0x7e for x in range(4, 49)] +
            [ast.variable(ctx.getSymbolicVariable(x))  != 0x00 for x in range(4, 49)]
          ))

    flag = str()
    for k, v in sorted(mod.items()):
        flag += chr(v.getValue())
    print('Flag: %s' %(flag))

    sys.exit(not (flag == 'CTF{0The1Quick2Brown3Fox4Jumped5Over6The7Lazy8Fox9}'))

def __malloc(ctx):
    global mallocCurrentAllocation
    global mallocMaxAllocation
    global mallocBase
    global mallocChunkSize


    print("into malloc")
    # Get arguments
    size =ctx.getConcreteRegisterValue(ctx.registers.rdi)

    if size > mallocChunkSize:
        sys.exit(-1)

    if mallocCurrentAllocation >= mallocMaxAllocation:
        sys.exit(-1)

    area = mallocBase + (mallocCurrentAllocation * mallocChunkSize)
    mallocCurrentAllocation += 1

    # Return value
    return area

def libcMainHandler(ctx):

    # Get arguments
    main = ctx.getConcreteRegisterValue(ctx.registers.rdi)

    # Push the return value to jump into the main() function
    ctx.setConcreteRegisterValue(ctx.registers.rsp, ctx.getConcreteRegisterValue(ctx.registers.rsp)-CPUSIZE.QWORD)

    ret2main = MemoryAccess(ctx.getConcreteRegisterValue(ctx.registers.rsp), CPUSIZE.QWORD)
    ctx.setConcreteMemoryValue(ret2main, main)

    # Setup argc / argv
    ctx.concretizeRegister(ctx.registers.rdi)
    ctx.concretizeRegister(ctx.registers.rsi)

    argvs = [
        bytes(TARGET.encode('utf-8')),  # argv[0]
        bytes(b'a' * 70),               # argv[1]
    ]

    # Define argc / argv
    base  = BASE_ARGV
    addrs = list()

    index = 0
    for argv in argvs:
        addrs.append(base)
        ctx.setConcreteMemoryAreaValue(base, argv+b'\x00')
        base += len(argv)+1
        index += 1

    argc = len(argvs)
    argv = base
    for addr in addrs:
        ctx.setConcreteMemoryValue(MemoryAccess(base, CPUSIZE.QWORD), addr)
        base += CPUSIZE.QWORD

    ctx.setConcreteRegisterValue(ctx.registers.rdi, argc)
    ctx.setConcreteRegisterValue(ctx.registers.rsi, argv)

    # Symbolize the first 51 bytes of the argv[1]
    argv1 = ctx.getConcreteMemoryValue(MemoryAccess(ctx.getConcreteRegisterValue(ctx.registers.rsi) + 8, CPUSIZE.QWORD))
    for index in range(51):
        var = ctx.symbolizeMemory(MemoryAccess(argv1+index, CPUSIZE.BYTE))

    return 0

def __free(ctx):
    print("________________free")
    return 0

def __fgets(ctx):

    # Get arguments
    arg1 =ctx.getConcreteRegisterValue(ctx.registers.rdi)
    arg2 =ctx.getConcreteRegisterValue(ctx.registers.rsi)

    indx = 0
    #user = raw_input("")[:arg2]
    user = "blah blah"

    for c in user:
        mem = MemoryAccess(arg1 + indx, CPUSIZE.BYTE)
        ctx.setConcreteMemoryValue(mem, ord(c))
        indx += 1

    # Return value
    return arg1

def __fopen(ctx):
    print("sssssssssssssss")
    return 1

def __fclose(ctx):
    print("sssssssssssssss")
    return 1

customRelocation = [
    ('__libc_start_main', libcMainHandler, BASE_PLT + 0),
    ('exit',              exitHandler,     BASE_PLT + 1),
    ('printf',            printfHandler,   BASE_PLT + 2),
    ('putchar',           putcharHandler,  BASE_PLT + 3),
    ('puts',              putsHandler,     BASE_PLT + 4),
    ('malloc',            __malloc,        BASE_PLT+6),
    ('free',            __free,        BASE_PLT+7),
    ('fgets',            __fgets,        BASE_PLT+8),
    ('fopen',            __fopen,        BASE_PLT+9),
    ('fclose',            __fclose,        BASE_PLT+10),
]
