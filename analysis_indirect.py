from triton  import *
from pintool import *

control_flow = list()

after_indirect = False
indirect_target_set = dict()

def before_inst(inst):
  global after_indirect
  global indirect_target_set
  global control_flow
  if after_indirect == True:
    if inst.getAddress() not in indirect_target_set:
      indirect_target_set[inst.getAddress()] = list()
    indirect_target_set[inst.getAddress()].append(getCurrentRegisterValue(REG.RIP))
    after_indirect = False

  if inst.isControlFlow():
    print 'meet branch: %x' % inst.getAddress()
    is_indirect = True
    if inst.isMemoryRead()==False and len(inst.getReadRegisters())==0:
      is_indirect = False
    if len(inst.getReadRegisters())==1 and inst.getReadRegisters()[0][0].getName()=='rsp':
      is_indirect = False
    if is_indirect == True:
      print 'meet indirect: %x' % inst.getAddress()
      for se in inst.getSymbolicExpressions():
        if se.isTainted() == True:
          print 'meet bug: ndirect with symbolic'
          detachProcess()
      after_indirect = True

    control_flow.append(inst.getAddress())

def before_syscall(threadId, std):
  if getSyscallNumber(std) == SYSCALL.READ:
    if isRegisterTainted(REG.RDX) is True:
      print 'unsupported'
      detachProcess()

def after_syscall(threadId, std):
  if getSyscallNumber(std) == SYSCALL.READ:
    mem_addr = getSyscallArgument(std, 1)
    mem_size = getSyscallArgument(std, 2)
    for i in range(0, mem_size):
      taintMemory(mem_addr + i)
    taintRegister(REG.RAX)

if __name__ == '__main__':
  setArchitecture(ARCH.X86_64)

  startAnalysisFromEntry()
  # startAnalysisFromAddress()
  # stopAnalysisFromAddress()

  insertCall(before_inst, INSERT_POINT.BEFORE)
  # insertCall(before_syscall, INSERT_POINT.SYSCALL_ENTRY)
  insertCall(after_syscall, INSERT_POINT.SYSCALL_EXIT)
  runProgram()
