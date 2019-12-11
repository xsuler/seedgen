from triton import TritonContext, ARCH, Instruction, MemoryAccess, CPUSIZE, MODE
import time
import pybloomfilter

import imp
import struct
import copy
import json
import sys
import lief
import random

gbinary = ''
addr_spec={}

Triton = TritonContext()
func_error_seed={}
addr_func={}


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
                    asts=(astCtxt.land(
                            [previousConstraints, branch['constraint']]))

                    models = Triton.getModel(asts)

                    seed = dict()
                    for k, v in list(models.items()):
                        symVar = Triton.getSymbolicVariable(k)
                        seed.update({symVar.getOrigin(): v.getValue()})
                    if seed:
                        inputs.append(seed)
        previousConstraints = (astCtxt.land(
            [previousConstraints, pc.getTakenPredicate()]))
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
            Triton.symbolizeMemory(MemoryAccess(address +i, 1))


def run(pc, seed):
    global func_error_seed
    call_stack=[]
    prev_seed=copy.deepcopy(seed)
    while pc:
        inst = Instruction()

        # Setup opcode
        opcode = Triton.getConcreteMemoryAreaValue(pc, 16)

        inst.setAddress(pc)

        arr = [hex(elem) for elem in opcode]
        if arr[:4] == ['0xf3', '0xf', '0x1e', '0xfa']:
            pc += 4
            continue
        if arr[:3] == ['0xf', '0x1', '0xd0']:
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
            call_stack.append(faddr)
            try:
                fopen_addr = gbinary.get_function_address("fopen")
                if fopen_addr == faddr:
                    mode = Triton.getConcreteRegisterValue(
                        Triton.registers.rsi)
                    buf_addr = 0x1000
                    size = 50
                    Triton.setConcreteRegisterValue(Triton.registers.rdi,
                                                    buf_addr)
                    Triton.setConcreteRegisterValue(Triton.registers.rsi, size)
                    Triton.setConcreteRegisterValue(Triton.registers.rdx, mode)
                    fmemopen_addr = gbinary.get_function_address("fmemopen")
                    offset = fmemopen_addr - pc - 5
                    opcode = struct.pack("<B", 0xe8) + struct.pack(
                        "<I", offset)

                    for i in range(size):
                        seed[0x1000 + i] = 10
                        seed[0x1000 + i + 1] = 10
            except:
                print("setted error")
                pass

            try:
                fclose_addr = gbinary.get_function_address("fclose")
                if fclose_addr == faddr:
                    pc += 5
                    continue
            except:
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
                putchar_addr = gbinary.get_function_address("putchar")
                if putchar_addr == faddr:
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
                fputs_addr = gbinary.get_function_address("puts")
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


            try:
                exit_addr = gbinary.get_function_address("exit")
                if exit_addr == faddr:
                    break
            except:
                pass

        inst.setOpcode(opcode)
        Triton.processing(inst)


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

            # print(str(hex(pc)) + " calling " + str(hex(faddr)))



        if arr[0] == '0xc3':
            if len(call_stack)>0:
                if call_stack[-1] in addr_spec:
                    raxv=Triton.getConcreteRegisterValue(Triton.registers.rax)
                    if satisfy(raxv,addr_spec[call_stack[-1]]):
                        func_error_seed[call_stack[-1]]=prev_seed
                call_stack.pop(-1)

        pc = Triton.getConcreteRegisterValue(Triton.registers.rip)
    return seed

def satisfy(value,sp):
    if sp[0] == '==':
        return value==sp[1]
    if sp[0] == '<':
        return value<sp[1]
    if sp[0] == '>':
        return value>sp[1]
    if sp[0] == '>=':
        return value>=sp[1]
    if sp[0] == '<=':
        return value<=sp[1]
    if sp[0] == '!=':
        return value!=sp[1]

def fix_keys(j):
    for k in copy.copy(j):
        j[int(k)] = j[k]
        j.pop(k)

class hdict(dict):
  def __key(self):
    return tuple((k,self[k]) for k in sorted(self))
  def __hash__(self):
    return hash(self.__key())
  def __eq__(self, other):
    return self.__key() == other.__key()

def simulate():
    global addr_spec,addr_func
    Triton.setArchitecture(ARCH.X86_64)
    Triton.setMode(MODE.ALIGNED_MEMORY, True)
    Triton.setMode(MODE.ONLY_ON_SYMBOLIZED, True)
    Triton.enableTaintEngine(False)


    ENTRY = loadBinary(sys.argv[1])

    spec = imp.load_source('name', './spec.py')
    func_spec=spec.func_spec

    addr_spec={}
    for func,sp in func_spec.items():
        addr_spec[gbinary.get_function_address(func)]=sp

    addr_func={}
    for func in func_spec:
        addr_func[gbinary.get_function_address(func)]=func


    lastInput =pybloomfilter.BloomFilter(100000,0.001,b'filter.bloom')

    worklist = [{}]

    while worklist:

        Triton.reset()
        Triton.setArchitecture(ARCH.X86_64)
        Triton.setMode(MODE.ALIGNED_MEMORY, True)
        Triton.setMode(MODE.ONLY_ON_SYMBOLIZED, True)
        Triton.enableTaintEngine(False)
        ENTRY = loadBinary(sys.argv[1])


        flag=0
        for addr in addr_spec:
            if addr not in func_error_seed:
                flag=1
        if flag==0:
            break

        seed = worklist[0]
        print("seed: " + str(seed))

        symbolizeInputs(seed)

        initContext()

        lastInput.add(hdict(seed))
        del worklist[0]
        run(ENTRY, seed)

        if hdict(seed) not in lastInput and seed not in worklist:
            worklist.append(seed)

        newInputs = getNewInput()
        for inputs in newInputs:
            if hdict(inputs) not in lastInput and inputs not in worklist:
                worklist.append(dict(inputs))
        print("seed "+str(len(worklist)))



simulate()
ret={}
for addr,func in addr_func.items():
    if addr in func_error_seed:
        seed=func_error_seed[addr]
        n_seed={}
        for adr,bina in seed.items():
            n_seed[adr-0x1000]=bina
        ret[func]=n_seed

seedfile=sys.argv[2]

with open(seedfile,"w") as f:
    res=json.dumps(ret)
    f.write(res)

print("seed"+str(ret))

