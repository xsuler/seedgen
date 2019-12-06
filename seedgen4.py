        # if arr[:2] == ['0f', '05']:
        #     raxv = Triton.getConcreteRegisterValue(Triton.registers.rax)
        #     if raxv == 0:
        #         buf = Triton.getConcreteRegisterValue(Triton.registers.rsi)
        #         size = Triton.getConcreteRegisterValue(Triton.registers.rdx)
        #         Triton.setConcreteRegisterValue(Triton.registers.rax, size)
        #         for i in range(size):
        #             if buf + i not in seed:
        #                 seed[buf + i] = 0
        #         pc += 2
        #         continue
        #     if raxv == 19:
        #         iovecptr = Triton.getConcreteRegisterValue(
        #             Triton.registers.rsi)
        #         vlen = Triton.getConcreteRegisterValue(Triton.registers.rdx)
        #         allsize = 0
        #         i = 0
        #         bufaddr = Triton.getConcreteMemoryAreaValue(
        #             iovecptr + 16 * i, 8)
        #         bufaddr = struct.unpack("<Q", bufaddr)[0]
        #         bufsize = Triton.getConcreteMemoryAreaValue(
        #             iovecptr + 16 * i + 8, 8)
        #         bufsize = struct.unpack("<Q", bufsize)[0]
        #         allsize += bufsize
        #         print(str(hex(bufaddr)))
        #         for idx in range(allsize):
        #             if bufaddr + idx not in seed:
        #                 seed[bufaddr + idx] = 0
        #         Triton.setConcreteRegisterValue(Triton.registers.rax,
        #                                         allsize+1)
        #         pc += 2
        #         continue
        #     if raxv == 8:
        #         pc += 2
        #         continue
