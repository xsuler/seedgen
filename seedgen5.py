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

visited_branch=set()

def run(pc, seed):
    global flagr
    prev=None
    prevpc=0
    while pc:
        inst = Instruction()

        # Setup opcode
        opcode = Triton.getConcreteMemoryAreaValue(pc, 16)

        inst.setOpcode(opcode)
        inst.setAddress(pc)
        arr = [elem.encode("hex") for elem in inst.getOpcode()]


        Triton.processing(inst)
        if pc==0x403cec:
            print("new ok")

        if prevpc not in visited_branch and prev!=None and prev.isBranch():
            visited_branch.add(prevpc)
            print("new branch "+str(hex(prevpc)))
            break
        prev=inst
        prevpc=pc


        print("inst: "+str(inst))

        if arr[:4] == ['f3', '0f', '1e', 'fa']:
            pc += 4
            continue
        if arr[:3] == ['0f', '01', 'd0']:
            pc += 3
            continue
        if arr[0] == 'f4':
            print("abort")
            break

        if arr[0] == 'e8':
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

            # print(str(hex(pc))+ " calling "+str(hex(faddr)))

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
                fread_addr = gbinary.get_function_address("fread")
                if fread_addr == faddr:
                    adr = Triton.getConcreteRegisterValue(Triton.registers.rdi)
                    num = Triton.getConcreteRegisterValue(
                        Triton.registers.rsi
                    ) * Triton.getConcreteRegisterValue(Triton.registers.rdx)
                    for i in range(num):
                        if adr + i not in seed:
                            # Triton.symbolizeMemory(MemoryAccess(adr + i, 1))
                            seed[adr + i] = 0
                    pc += 5

                    Triton.setConcreteRegisterValue(Triton.registers.rax, num)
                    continue
            except:
                pass

            try:
                fseek_addr = gbinary.get_function_address("fseek")
                if fseek_addr == faddr:
                    Triton.setConcreteRegisterValue(Triton.registers.rax, 0)
                    pc += 5
                    continue
            except:
                pass
        pc = Triton.getRegisterAst(Triton.registers.rip).evaluate()
    return seed


def fix_keys(j):
    for k in copy.copy(j):
        j[int(k)] = j[k]
        j.pop(k)


lastInput = list()
def simulate():
    global lastInput
    Triton.setArchitecture(ARCH.X86_64)
    Triton.setMode(MODE.ALIGNED_MEMORY, True)

    ENTRY = loadBinary(sys.argv[1])
    run(ENTRY, {})
    worklist = [{}]

    while True:
        if not worklist:
            worklist=[{}]
        seed = worklist[0]
        print("seed: " + str(seed))

        symbolizeInputs(seed)

        initContext()

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
