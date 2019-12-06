from __future__ import print_function
from triton     import TritonContext, ARCH, Instruction, MemoryAccess, CPUSIZE, MODE
from reloc import *
import  sys
import os
import string
import lief

# TODO add max checker and break
# TODO hooking handler normal
Triton = TritonContext()

addrs={}
protocol_type=0
gbinary=''

def loadBinary(path):
    global gbinary
    binary = lief.parse(path)
    phdrs  = binary.segments
    for phdr in phdrs:
        size   = phdr.physical_size
        vaddr  = phdr.virtual_address
        Triton.setConcreteMemoryAreaValue(vaddr, phdr.content)
    # makeRelocation(Triton, binary)
    gbinary=binary
    if protocol_type==1:
        return binary.get_function_address("protocol")
    else:
        return binary.get_function_address("main")


# This function emulates the code.
def run(pc,func_spec,seed):
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

        if arr[0]=='e8':
            offset=0
            offset+=int(arr[4],16)
            offset=offset<<8
            offset+=int(arr[3],16)
            offset=offset<<8
            offset+=int(arr[2],16)
            offset=offset<<8
            offset+=int(arr[1],16)
            faddr=offset+pc+5
            faddr=faddr&0xffffffff

            try:
                fclose_addr=gbinary.get_function_address("fclose")
                if fclose_addr==faddr:
                    pc+=5
                    continue
            except:
                pass

            try:
               fgets_addr=gbinary.get_function_address("fgets")
               if fgets_addr==faddr:
                    adr=Triton.getConcreteRegisterValue(Triton.registers.rdi)
                    num=Triton.getConcreteRegisterValue(Triton.registers.rsi)
                    for i in range(num):
                        if adr+i not in seed:
                            seed[adr+i]=0

                    pc+=5
                    continue
            except:
                pass

            try:
               fread_addr=gbinary.get_function_address("fread")
               if fread_addr==faddr:
                    adr=Triton.getConcreteRegisterValue(Triton.registers.rdi)
                    num=Triton.getConcreteRegisterValue(Triton.registers.rsi)*Triton.getConcreteRegisterValue(Triton.registers.rdx)
                    for i in range(num):
                        if adr+i not in seed:
                            print("new fread")
                            seed[adr+i]=0

                    pc+=5
                    continue
            except:
                pass

            try:
               printf_addr=gbinary.get_function_address("printf")
               if printf_addr==faddr:
                    pc+=5
                    continue
            except:
                pass

            try:
               fprintf_addr=gbinary.get_function_address("fprintf")
               if fprintf_addr==faddr:
                    pc+=5
                    continue
            except:
                pass

 

        if arr[0]=='e8' and flag==0:
            offset=0
            offset+=int(arr[4],16)
            offset=offset<<8
            offset+=int(arr[3],16)
            offset=offset<<8
            offset+=int(arr[2],16)
            offset=offset<<8
            offset+=int(arr[1],16)
            addr=offset+pc+5
            addr=addr&0xffffffff

            if addr in func_spec:
                last_op=addr
                if func_spec[addr][0]in ["==",">=","<="]:
                    Triton.setConcreteRegisterValue(Triton.registers.rax,func_spec[addr][1])
                if func_spec[addr][0]=='>':
                    Triton.setConcreteRegisterValue(Triton.registers.rax,func_spec[addr][1]+1)
                if func_spec[addr][0]=='!=':
                    Triton.setConcreteRegisterValue(Triton.registers.rax,func_spec[addr][1]+1)
                if func_spec[addr][0]=='<':
                    Triton.setConcreteRegisterValue(Triton.registers.rax,func_spec[addr][1]-1)
                flag=1
                pc+=5
                continue
        Triton.processing(inst)

        gflag=0
        for addr in func_spec:
            if addr not in addrs:
                gflag=1
                break
        if gflag==0:
            break

        if flag==2:
            addrs[last_op]=pc
            flag=0
        if flag==1:
            if inst.isBranch():
                flag=2


        # hookingHandler(Triton)
        pc =Triton.getConcreteRegisterValue(Triton.registers.rip)



def runR(pc,binary):
    seed={}
    while pc:
        # Build an instruction
        inst = Instruction()

        # Setup opcode
        opcode=Triton.getConcreteMemoryAreaValue(pc, 16)

        inst.setOpcode(opcode)
        inst.setAddress(pc)

        arr=[elem.encode("hex") for elem in inst.getOpcode()]
        # endbr64
        if arr[:4]==['f3', '0f', '1e', 'fa']:
            pc+=4
            continue
        if arr[:3]==['0f', '01', 'd0']:
            pc+=3
            continue
        if arr[0]=='f4':
            print("abort")
            break

        if arr[0]=='e8':
            offset=0
            offset+=int(arr[4],16)
            offset=offset<<8
            offset+=int(arr[3],16)
            offset=offset<<8
            offset+=int(arr[2],16)
            offset=offset<<8
            offset+=int(arr[1],16)
            faddr=offset+pc+5
            faddr=faddr&0xffffffff
            print(str(hex(pc))+" calling: "+str(hex(faddr)))

            try:
                fclose_addr=binary.get_function_address("fclose")
                if fclose_addr==faddr:
                    pc+=5
                    continue
            except:
                pass

            try:
               fgets_addr=binary.get_function_address("fgets")
               if fgets_addr==faddr:
                    adr=Triton.getConcreteRegisterValue(Triton.registers.rdi)
                    num=Triton.getConcreteRegisterValue(Triton.registers.rsi)
                    for i in range(num):
                        seed[adr+i]=0

                    pc+=5
                    continue
            except:
                pass

            try:
               fread_addr=binary.get_function_address("fread")
               if fread_addr==faddr:
                    print("fread at "+str(hex(pc)))
                    adr=Triton.getConcreteRegisterValue(Triton.registers.rdi)
                    num=Triton.getConcreteRegisterValue(Triton.registers.rsi)*Triton.getConcreteRegisterValue(Triton.registers.rdx)
                    for i in range(num):
                        seed[adr+i]=0

                    pc+=5
                    continue
            except:
                pass
            try:
               printf_addr=binary.get_function_address("printf")
               if printf_addr==faddr:
                    pc+=5
                    continue
            except:
                pass

            try:
               fprintf_addr=binary.get_function_address("fprintf")
               if fprintf_addr==faddr:
                    pc+=5
                    continue
            except:
                pass



        Triton.processing(inst)


        # Setup Address


        # hookingHandler(Triton)
        pc =Triton.getConcreteRegisterValue(Triton.registers.rip)
    return seed




def initContext():
    # Point RDI on our buffer. The address of our buffer is arbitrary. We just need
    # to point the RDI register on it as first argument of our targeted function.
    if protocol_type==0:
        Triton.setConcreteMemoryValue(0x900008, 0x00)
        Triton.setConcreteMemoryValue(0x900009, 0x10)

        Triton.setConcreteRegisterValue(Triton.registers.rsi, 0x900000)
    elif protocol_type==1:
        Triton.setConcreteRegisterValue(Triton.registers.rdi, 0x1000)

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
    print(pco)

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

def find_fgets_seed(ENTRY,binary):
    initContext()
    seed=runR(ENTRY,binary)
    return seed


def get_address(func_spec,protocol_typer,binary,filen):
    global protocol_type
    protocol_type=protocol_typer
    # Set the architecture
    Triton.setArchitecture(ARCH.X86_64)

    # Symbolic optimization
    Triton.setMode(MODE.ALIGNED_MEMORY, True)
    ENTRY=loadBinary(os.path.join(os.path.dirname(__file__), filen))


    # We start the execution with a random value located at 0x1000.
    lastInput = list()
    if protocol_type==2:
        worklist=[find_fgets_seed(ENTRY,binary)]
    else:
        worklist  = list([{0x1000:0x64}])
 
    while worklist:
        # Take the first seed
        seed = worklist[0]

        # Symbolize inputs
        symbolizeInputs(seed)

        # Init context memory
        initContext()

        # Emulate
        run(ENTRY,func_spec,seed)

        lastInput += [dict(seed)]
        del worklist[0]

        newInputs = getNewInput()
        for inputs in newInputs:
            if inputs not in lastInput and inputs not in worklist:
                worklist += [dict(inputs)]

    return addrs
