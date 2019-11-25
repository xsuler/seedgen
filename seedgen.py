
from __future__ import print_function
from triton     import TritonContext, ARCH, Instruction, MemoryAccess, CPUSIZE, MODE
from locate import get_address
from reloc import *
import  sys
import os
import string
import lief

Triton = TritonContext()
seeds={}


def loadBinary(path):
    binary = lief.parse(path)
    phdrs  = binary.segments
    for phdr in phdrs:
        size   = phdr.physical_size
        vaddr  = phdr.virtual_address
        Triton.setConcreteMemoryAreaValue(vaddr, phdr.content)
    return binary.get_function_address("main"),binary


# This function emulates the code.
def run(pc,seed):
    global seeds
    while pc:
        if pc in seeds:
            seeds[pc]=seed
        # Build an instruction
        inst = Instruction()

        # Setup opcode
        opcode=Triton.getConcreteMemoryAreaValue(pc, 16)

        inst.setOpcode(opcode)
        inst.setAddress(pc)
        arr=[elem.encode("hex") for elem in inst.getOpcode()]
        if arr[:4]==['f3', '0f', '1e', 'fa']:
            print("here")
            pc+=4
            continue
        if arr[:3]==['0f', '01', 'd0']:
            pc+=3
            continue
        if arr[0]=='f4':
            print("abort")
            break

        # Setup Address

        Triton.processing(inst)

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




def getSeeds(addrs,ENTRY):
    # Set the architecture
    Triton.setMode(MODE.ALIGNED_MEMORY, True)

    # We start the execution with a random value located at 0x1000.
    lastInput = list()
    worklist  = list([{0x1000:0x64}])
    for addr in addrs:
        seeds[addr]=0

    while worklist:
        # Take the first seed
        seed = worklist[0]

        # Symbolize inputs
        symbolizeInputs(seed)

        # Init context memory
        initContext()

        # Emulate
        run(ENTRY,seed)

        lastInput += [dict(seed)]
        del worklist[0]

        newInputs = getNewInput()
        for inputs in newInputs:
            if inputs not in lastInput and inputs not in worklist:
                worklist += [dict(inputs)]

    return seeds

if __name__ == '__main__':
    Triton.setArchitecture(ARCH.X86_64)

    # Symbolic optimization
 
    ENTRY,binary=loadBinary(os.path.join(os.path.dirname(__file__), 'a.out'))
    func_spec={
        "check":['>',1],
        "check1":['>',1]
    }
    func_addr_name_map={}
    for func in func_spec:
        func_addr_name_map[binary.get_function_address(func)]=func
    spec={}
    for func,sp in func_spec.items():
        spec[binary.get_function_address(func)]=sp
    addrs=get_address(spec)
    ret=getSeeds(addrs,ENTRY)
    res={}
    for addr,seed in ret.items():
        res[func_addr_name_map[addr]]=seed

    print(addrs)
    print(res)

    sys.exit(0)
