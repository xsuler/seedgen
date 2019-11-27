from __future__ import print_function
from triton     import TritonContext, ARCH, Instruction, MemoryAccess, CPUSIZE, MODE
from reloc import *
import  sys
import os
import string
import lief

Triton = TritonContext()

addrs={}
option=0

def loadBinary(path):
    binary = lief.parse(path)
    phdrs  = binary.segments
    for phdr in phdrs:
        size   = phdr.physical_size
        vaddr  = phdr.virtual_address
        Triton.setConcreteMemoryAreaValue(vaddr, phdr.content)
    # makeRelocation(Triton, binary)
    if option==1:
        return binary.get_function_address("protocol")
    else:
        return binary.get_function_address("main")


# This function emulates the code.
def run(pc,func_spec):
    global addrs
    flag=0
    while pc:
        inst = Instruction()

        # Setup opcode
        opcode=Triton.getConcreteMemoryAreaValue(pc, 16)

        inst.setOpcode(opcode)
        inst.setAddress(pc)
        arr=[elem.encode("hex") for elem in inst.getOpcode()]
        if arr[:4]==['f3', '0f', '1e', 'fa']:
            pc+=4
            continue
        if arr[:3]==['0f', '01', 'd0']:
            pc+=3
            continue
        if arr[0]=='f4':
            print("abort")
            break
        Triton.processing(inst)

        if arr[0]=='e8' and flag==0:
            addr=inst.getOperands()[0].getValue()
            if addr in func_spec:
                last_op=addr
                if func_spec[addr][0]in ["==",">=","<="]:
                    Triton.setConcreteRegisterValue(Triton.registers.rax,func_spec[addr][1])
                if func_spec[addr][0]=='>':
                    Triton.setConcreteRegisterValue(Triton.registers.rax,func_spec[addr][1]+1)
                if func_spec[addr][0]=='<':
                    Triton.setConcreteRegisterValue(Triton.registers.rax,func_spec[addr][1]-1)
                flag=1
                pc+=5
                continue

        if flag==2:
            addrs[last_op]=pc
            flag=0
        if flag==1:
            if inst.isBranch():
                flag=2


        # hookingHandler(Triton)
        pc =Triton.getConcreteRegisterValue(Triton.registers.rip)



# This function initializes the context memory.
def initContext():
    # Point RDI on our buffer. The address of our buffer is arbitrary. We just need
    # to point the RDI register on it as first argument of our targeted function.
    Triton.setConcreteMemoryValue(0x900008, 0x00)
    Triton.setConcreteMemoryValue(0x900009, 0x10)

    Triton.setConcreteRegisterValue(Triton.registers.rsi, 0x900000)

    # Setup stack on an abitrary address.
    Triton.setConcreteRegisterValue(Triton.registers.rsp, 0x7fffffff)
    Triton.setConcreteRegisterValue(Triton.registers.rbp, 0x7fffffff)
    return



# This function returns a set of new inputs based on the last trace.
def getNewInput():
    # Set of new inputs
    inputs = list()

    # Get path constraints from the last execution
    pco = Triton.getPathConstraints()

    # Get the astContext
    astCtxt = Triton.getAstContext()

    # We start with any input. T (Top)
    previousConstraints = astCtxt.equal(astCtxt.bvtrue(), astCtxt.bvtrue())

    # Go through the path constraints
    for pc in pco:
        # If there is a condition
        if pc.isMultipleBranches():
            # Get all branches
            branches = pc.getBranchConstraints()
            for branch in branches:
                # Get the constraint of the branch which has been not taken
                if branch['isTaken'] == False:
                    # Ask for a model
                    models = Triton.getModel(astCtxt.land([previousConstraints, branch['constraint']]))
                    seed   = dict()
                    for k, v in list(models.items()):
                        # Get the symbolic variable assigned to the model
                        symVar = Triton.getSymbolicVariable(k)
                        # Save the new input as seed.
                        seed.update({symVar.getOrigin(): v.getValue()})
                    if seed:
                        inputs.append(seed)

        # Update the previous constraints with true branch to keep a good path.
        previousConstraints = astCtxt.land([previousConstraints, pc.getTakenPredicate()])

    # Clear the path constraints to be clean at the next execution.
    Triton.clearPathConstraints()

    return inputs

def symbolizeInputs(seed):
    Triton.concretizeAllRegister()
    Triton.concretizeAllMemory()
    for address, value in list(seed.items()):
        Triton.setConcreteMemoryValue(MemoryAccess(address, 1), value)
        for i in range(100):
            Triton.symbolizeMemory(MemoryAccess(address+i, 1))
    return


def get_address(func_spec,optionr):
    global option
    option=optionr
    # Set the architecture
    Triton.setArchitecture(ARCH.X86_64)

    # Symbolic optimization
    Triton.setMode(MODE.ALIGNED_MEMORY, True)
    ENTRY=loadBinary(os.path.join(os.path.dirname(__file__), 'a.out'))


    # We start the execution with a random value located at 0x1000.
    lastInput = list()
    worklist  = list([{0x1000:0x64}])

    while worklist:
        # Take the first seed
        seed = worklist[0]

        # Symbolize inputs
        symbolizeInputs(seed)

        # Init context memory
        initContext()

        # Emulate
        run(ENTRY,func_spec)

        lastInput += [dict(seed)]
        del worklist[0]

        newInputs = getNewInput()
        for inputs in newInputs:
            if inputs not in lastInput and inputs not in worklist:
                worklist += [dict(inputs)]

    return addrs
