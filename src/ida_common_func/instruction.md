# Instruction=指令

```python
# class Instruction(object):
class Instruction:
  # toStr = "to"
  toStr = "To"
  # addStr = "add"
  addStr = "Add"

  def __init__(self, addr, name, operands):
    self.addr = addr
    self.disAsmStr = ida_getDisasmStr(addr)
    # print("self.disAsmStr=%s" % self.disAsmStr)
    self.name = name
    self.operands = operands

  def __str__(self):
    # operandsAllStr = Operand.listToStr(self.operands)
    # print("operandsAllStr=%s" % operandsAllStr)
    # curInstStr = "<Instruction: addr=0x%X,name=%s,operands=%s>" % (self.addr, self.name, operandsAllStr)
    # curInstStr = "<Instruction: addr=0x%X,disAsmStr=%s>" % (self.addr, self.disAsmStr)
    curInstStr = "<Instruction: 0x%X: %s>" % (self.addr, self.disAsmStr)
    # print("curInstStr=%s" % curInstStr)
    return curInstStr

  @staticmethod
  def listToStr(instList):
    instContentStrList = [str(eachInst) for eachInst in instList]
    instListAllStr = ", ".join(instContentStrList)
    instListAllStr = "[%s]" % instListAllStr
    return instListAllStr

  @staticmethod
  def parse(addr):
    isDebug = False
    # # if addr == 0x10235D610:
    # # if addr == 0x1002B8340:
    # if addr == 0x102390B18:
    #   isDebug = True
    # isDebug = True

    if isDebug:
      print("Instruction: parsing 0x%X" % addr)
    parsedInst = None

    instName = idc.print_insn_mnem(addr)
    if isDebug:
      print("instName=%s" % instName)

    curOperandIdx = 0
    curOperandVaild = True
    operandList = []
    while curOperandVaild:
      if isDebug:
        logSubSub("[%d]" % curOperandIdx)
      curOperand = idc.print_operand(addr, curOperandIdx)
      if isDebug:
        print("curOperand=%s" % curOperand)
      curOperandType = idc.get_operand_type(addr, curOperandIdx)
      if isDebug:
        print("curOperandType=%d" % curOperandType)
      curOperandValue = idc.get_operand_value(addr, curOperandIdx)
      if isDebug:
        print("curOperandValue=%s=0x%X" % (curOperandValue, curOperandValue))
      curOperand = Operand(curOperand, curOperandType, curOperandValue)
      if isDebug:
        print("curOperand=%s" % curOperand)
      if curOperand.isValid():
        operandList.append(curOperand)
      else:
        if isDebug:
          print("End of operand for invalid %s" % curOperand)
        curOperandVaild = False

      if isDebug:
        print("curOperandVaild=%s" % curOperandVaild)
      curOperandIdx += 1

    if operandList:
      parsedInst = Instruction(addr=addr, name=instName, operands=operandList)
    if isDebug:
      print("parsedInst=%s" % parsedInst)
      print("operandList=%s" % Operand.listToStr(operandList))
    return parsedInst

  def isInst(self, instName):
    isMatchInst = False
    if self.name:
      if (instName.lower() == self.name.lower()):
        isMatchInst = True
    return isMatchInst

  @property
  def contentStr(self):
    """
    convert to meaningful string of Instruction real action / content
    """
    contentStr = ""

    isDebug = False
    # isDebug = True

    if isDebug:
      print("self=%s" % self)

    operandNum = len(self.operands)
    if isDebug:
      print("operandNum=%s" % operandNum)
    
    isPairInst = self.isStp() or self.isLdp()
    if isDebug:
      print("isPairInst=%s" % isPairInst)
    if not isPairInst:
      if operandNum >= 2:
        srcOperand = self.operands[1]
        if isDebug:
          print("srcOperand=%s" % srcOperand)
        srcOperandStr = srcOperand.contentStr
        if isDebug:
          print("srcOperandStr=%s" % srcOperandStr)
        dstOperand = self.operands[0]
        if isDebug:
          print("dstOperand=%s" % dstOperand)
        dstOperandStr = dstOperand.contentStr
        if isDebug:
          print("dstOperandStr=%s" % dstOperandStr)

    if self.isMov() or self.isFmov():
      # MOV X0, X24
      # FMOV D4, #-3.0

      if operandNum == 2:
        contentStr = "%s%s%s" % (srcOperandStr, Instruction.toStr, dstOperandStr)
        # print("contentStr=%s" % contentStr)
      elif operandNum > 2:
        # TODO: add case for operand > 2
        print("TODO: add support operand > 2 of MOV/FMOV")
    elif self.isAdd() or self.isFadd():
      # <Instruction: 0x10235D574: ADD X0, X19, X8; location>
      # # print("is ADD: self=%s" % self)
      # instName = self.name
      # # print("instName=%s" % instName)
      # instOperandList = self.operands
      # # print("instOperandList=%s" % Operand.listToStr(instOperandList))
      if operandNum == 3:
        # <Instruction: 0x10235D574: ADD X0, X19, X8; location>
        extracOperand = self.operands[2]
        # print("extracOperand=%s" % extracOperand)
        extraOperandStr = extracOperand.contentStr
        # print("extraOperandStr=%s" % extraOperandStr)
        contentStr = "%s%s%s%s%s" % (srcOperandStr, Instruction.addStr, extraOperandStr, Instruction.toStr, dstOperandStr)

      # TODO: add case operand == 2
    elif self.isLdr():
      # LDR X0, [SP,#arg_18];
      if operandNum == 2:
        contentStr = "%s%s%s" % (srcOperandStr, Instruction.toStr, dstOperandStr)
      elif operandNum > 2:
        # TODO: add case for operand > 2
        print("TODO: add support operand > 2 of LDR")
    elif self.isStr():
      # STR XZR, [X19,X8]
      if operandNum == 2:
        contentStr = "%s%s%s" % (dstOperandStr, Instruction.toStr, srcOperandStr)
      elif operandNum > 2:
        # TODO: add case for operand > 2
        print("TODO: add support operand > 2 of STR")
    elif self.isStp():
      # <Instruction: 0x10235D6B4: STP X8, X9, [SP,#arg_18]>
      if operandNum == 3:
        srcOperand1 = self.operands[0]
        if isDebug:
          print("srcOperand1=%s" % srcOperand1)
        srcOperand1Str = srcOperand1.contentStr
        if isDebug:
          print("srcOperand1Str=%s" % srcOperand1Str)
        srcOperand2 = self.operands[1]
        if isDebug:
          print("srcOperand2=%s" % srcOperand2)
        srcOperand2Str = srcOperand2.contentStr
        if isDebug:
          print("srcOperand2Str=%s" % srcOperand2Str)

        dstOperand = self.operands[2]
        if isDebug:
          print("dstOperand=%s" % dstOperand)
        dstOperandStr = dstOperand.contentStr
        if isDebug:
          print("dstOperandStr=%s" % dstOperandStr)
        
        contentStr = "%s%s%s%s" % (srcOperand1Str, srcOperand2Str, Instruction.toStr, dstOperandStr)
    elif self.isLdp():
      # <Instruction: 0x10235D988: LDP D0, D1, [X8]>
      # <Instruction: 0x10235D98C: LDP D2, D3, [X8,#0x10]>
      if operandNum == 3:
        dstOperand1 = self.operands[0]
        if isDebug:
          print("dstOperand1=%s" % dstOperand1)
        dstOperand1Str = dstOperand1.contentStr
        if isDebug:
          print("dstOperand1Str=%s" % dstOperand1Str)
        dstOperand2 = self.operands[1]
        if isDebug:
          print("dstOperand2=%s" % dstOperand2)
        dstOperand2Str = dstOperand2.contentStr
        if isDebug:
          print("dstOperand2Str=%s" % dstOperand2Str)

        srcOperand = self.operands[2]
        if isDebug:
          print("srcOperand=%s" % srcOperand)
        srcOperandStr = srcOperand.contentStr
        if isDebug:
          print("srcOperandStr=%s" % srcOperandStr)
        
        contentStr = "%s%s%s%s" % (srcOperandStr, Instruction.toStr, dstOperand1Str, dstOperand2Str)

    # TODO: add other Instruction support: SUB/STR/...
    if isDebug:
      print("contentStr=%s" % contentStr)
    return contentStr

  def isMov(self):
    return self.isInst("MOV")

  def isFmov(self):
    return self.isInst("FMOV")

  def isRet(self):
    return self.isInst("RET")

  def isB(self):
    return self.isInst("B")

  def isBr(self):
    return self.isInst("BR")

  def isBranch(self):
    # TODO: support more: BRAA / ...
    return self.isB() or self.isBr()

  def isAdd(self):
    return self.isInst("ADD")

  def isFadd(self):
    return self.isInst("FADD")

  def isSub(self):
    return self.isInst("SUB")

  def isStr(self):
    return self.isInst("STR")

  def isStp(self):
    return self.isInst("STP")

  def isLdp(self):
    return self.isInst("LDP")

  def isLdr(self):
    return self.isInst("LDR")
```
