from triton import TritonContext, ARCH, Instruction, MemoryAccess, CPUSIZE, MODE
import struct
import copy
import json
import sys
import lief

gbinary = ''

Triton = TritonContext()


def loadBinary(path):
    global gbinary
    binary = lief.parse(path)
    phdrs = binary.segments
    for phdr in phdrs:
        size = phdr.physical_size
        vaddr = phdr.virtual_address
        Triton.setConcreteMemoryAreaValue(vaddr, phdr.content)
    gbinary = binary
    return binary.get_function_address("main")


def getNewInput():
    inputs = list()
    pco = Triton.getPathConstraints()
    astCtxt = Triton.getAstContext()
    previousConstraints = astCtxt.equal(astCtxt.bvtrue(), astCtxt.bvtrue())
    for pc in pco:
        if pc.isMultipleBranches():
            branches = pc.getBranchConstraints()
            for branch in branches:
                if branch['isTaken'] == False:
                    models = Triton.getModel(
                        astCtxt.land(
                            [previousConstraints, branch['constraint']]))
                    seed = dict()
                    for k, v in list(models.items()):
                        symVar = Triton.getSymbolicVariable(k)
                        seed.update({symVar.getOrigin(): v.getValue()})
                    if seed:
                        inputs.append(seed)
        previousConstraints = astCtxt.land(
            [previousConstraints, pc.getTakenPredicate()])
    Triton.clearPathConstraints()
    return inputs


def initContext():
    Triton.setConcreteRegisterValue(Triton.registers.rsp, 0x7fffffff)
    Triton.setConcreteRegisterValue(Triton.registers.rbp, 0x7fffffff)


def symbolizeInputs(seed):
    Triton.concretizeAllRegister()
    Triton.concretizeAllMemory()
    for address, value in list(seed.items()):
        Triton.setConcreteMemoryValue(MemoryAccess(address, 1), value)
        for i in range(100):
            Triton.symbolizeMemory(MemoryAccess(address + i, 1))


def run(pc, seed):
    global flagr
    while pc:
        inst = Instruction()

        # Setup opcode
        opcode = Triton.getConcreteMemoryAreaValue(pc, 16)

        inst.setAddress(pc)

        arr = [hex(elem) for elem in opcode]

        if arr[0] == '0xe8':
            offset = 0
            offset += int(arr[4], 16)
            offset = offset << 8
            offset += int(arr[3], 16)
            offset = offset << 8
            offset += int(arr[2], 16)
            offset = offset << 8
            offset += int(arr[1], 16)
            faddr = offset + pc + 5
            faddr = faddr & 0xffffffff
            try:
                fopen_addr = gbinary.get_function_address("fopen")
                if fopen_addr == faddr:
                    mode = Triton.getConcreteRegisterValue(
                        Triton.registers.rsi)
                    print("setted 0")
                    buf_addr = 0x1000
                    size = 100
                    Triton.setConcreteRegisterValue(Triton.registers.rdi,
                                                    buf_addr)
                    Triton.setConcreteRegisterValue(Triton.registers.rsi, size)
                    Triton.setConcreteRegisterValue(Triton.registers.rdx, mode)
                    print("setted 1")
                    fmemopen_addr = gbinary.get_function_address("fmemopen")
                    print("setted 2")
                    offset = fmemopen_addr - pc - 5
                    opcode = struct.pack("<B", 0xe8) + struct.pack(
                        "<I", offset)
                    print("setted")

                    for i in range(size):
                        seed[0x1000 + i] = 10
                        seed[0x1000 + i + 1] = 10
            except:
                print("setted error")
                pass

            try:
                malloc_addr = gbinary.get_function_address("malloc")
                if malloc_addr == faddr:
                    Triton.setConcreteRegisterValue(Triton.registers.rax,
                                                    0x4000)
                    pc += 5
                    continue
            except:
                pass

            try:
                printf_addr = gbinary.get_function_address("printf")
                if printf_addr == faddr:
                    pc += 5
                    continue
            except:
                pass


            try:
                fprintf_addr = gbinary.get_function_address("fprintf")
                if fprintf_addr == faddr:
                    pc += 5
                    continue
            except:
                pass

            try:
                fputc_addr = gbinary.get_function_address("fputc")
                if fputc_addr == faddr:
                    pc += 5
                    continue
            except:
                pass

            try:
                fputc_addr = gbinary.get_function_address("fputc")
                if fputc_addr == faddr:
                    pc += 5
                    continue
            except:
                pass

            try:
                fputchar_addr = gbinary.get_function_address("fputchar")
                if fputchar_addr == faddr:
                    pc += 5
                    continue
            except:
                pass
            try:
                fputs_addr = gbinary.get_function_address("fputs")
                if fputs_addr == faddr:
                    pc += 5
                    continue
            except:
                pass



            try:
                fwrite_addr = gbinary.get_function_address("fwrite")
                if fwrite_addr == faddr:
                    pc += 5
                    continue
            except:
                pass




        inst.setOpcode(opcode)
        Triton.processing(inst)
        print(inst)

        if arr[:4] == ['0xf3', '0x0f', '0x1e', '0xfa']:
            pc += 4
            continue
        if arr[:3] == ['0x0f', '0x01', '0xd0']:
            pc += 3
            continue
        if arr[0] == '0xf4':
            print("abort")
            break

        if arr[0] == '0xe8':
            offset = 0
            offset += int(arr[4], 16)
            offset = offset << 8
            offset += int(arr[3], 16)
            offset = offset << 8
            offset += int(arr[2], 16)
            offset = offset << 8
            offset += int(arr[1], 16)
            faddr = offset + pc + 5
            faddr = faddr & 0xffffffff

            print(str(hex(pc)) + " calling " + str(hex(faddr)))

        pc = Triton.getConcreteRegisterValue(Triton.registers.rip)
    return seed


def fix_keys(j):
    for k in copy.copy(j):
        j[int(k)] = j[k]
        j.pop(k)


def simulate():
    Triton.setArchitecture(ARCH.X86_64)
    Triton.setMode(MODE.ALIGNED_MEMORY, True)

    ENTRY = loadBinary(sys.argv[1])
    lastInput = list()
    run(ENTRY, {})
    worklist = [{}]

    while worklist:
        # Take the first seed
        seed = worklist[0]
        print("seed: " + str(seed))

        # Symbolize inputs
        symbolizeInputs(seed)

        # Init context memory
        initContext()

        # Emulate
        lastInput += [dict(seed)]
        del worklist[0]
        run(ENTRY, seed)

        if seed not in lastInput:
            worklist.append(seed)

        newInputs = getNewInput()
        for inputs in newInputs:
            if inputs not in lastInput and inputs not in worklist:
                worklist += [dict(inputs)]


simulate()
