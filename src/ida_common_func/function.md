# IDA函数

* 概述
  * 关于IDA的Python脚本代码中常用的函数，已整理至
    * [crifanIDA.py](https://github.com/crifan/crifanLibPython/blob/master/python3/crifanLib/thirdParty/crifanIDA.py)
  * 使用举例
    * [AutoRename.py](https://github.com/crifan/AutoRename/blob/main/AutoRename.py)
    * [exportIDASymbol.py](https://github.com/crifan/restore-symbol/blob/master/tools/IDAScripts/export_ida_symbol/exportIDASymbol.py)
    * [ida_search_block.py](https://github.com/crifan/restore-symbol/blob/master/tools/IDAScripts/search_oc_block/ida_search_block.py)

* 详解

## 辅助内容

#### 导入IDA的库

```python
import re
import os

import idc
import idaapi
import idautils
import ida_nalt
import ida_segment
```

#### 辅助函数

* [crifaniOS.py](https://github.com/crifan/crifanLibPython/blob/master/python3/crifanLib/thirdParty/crifaniOS.py)

##### isObjcFunctionName

```python
def isObjcFunctionName(funcName):
  """
  check is ObjC function name or not
  eg:
    "+[WAAvatarStringsActions editAvatar]" -> True
    "-[ParentGroupInfoViewController initWithParentGroupChatSession:userContext:recentlyLinkedGroupJIDs:]" -> True
    "-[OKEvolveSegmentationVC proCard]_116" -> True
    "-[WAAvatarStickerUpSellSupplementaryView .cxx_destruct]" -> True
    "sub_10004C6D8" -> False
    "protocol witness for RawRepresentable.init(rawValue:) in conformance UIFont.FontWeight" -> True
  """
  isMatchObjcFuncName = re.match("^[\-\+]\[\w+ [\w\.\:]+\]\w*$", funcName)
  isObjcFuncName = bool(isMatchObjcFuncName)
  # print("funcName=%s -> isObjcFuncName=%s" % (funcName, isObjcFuncName))
  return isObjcFuncName
```

## IDA常用函数

### ida_getInfo

```python
def ida_getInfo():
  """
  get IDA info
  """
  info = idaapi.get_inf_structure()
  # print("info=%s" % info)
  return info
```

### ida_printInfo

```python
def ida_printInfo(info):
  """
  print IDA info
  """
  version = info.version
  print("version=%s" % version)
  is64Bit = info.is_64bit()
  print("is64Bit=%s" % is64Bit)
  procName = info.procname
  print("procName=%s" % procName)
  entryPoint = info.start_ea
  print("entryPoint=0x%X" % entryPoint)
  baseAddr = info.baseaddr
  print("baseAddr=0x%X" % baseAddr)

```

### ida_printAllImports

```python
def ida_printAllImports():
  """
  print all imports lib and functions inside lib"""
  nimps = ida_nalt.get_import_module_qty()
  print("Found %d import(s)..." % nimps)
  for i in range(nimps):
    name = ida_nalt.get_import_module_name(i)
    if not name:
      print("Failed to get import module name for [%d] %s" % (i, name))
      name = "<unnamed>"
    else:
      print("[%d] %s" % (i, name))

    def imp_cb(ea, name, ordinal):
        if not name:
            print("%08x: ordinal #%d" % (ea, ordinal))
        else:
            print("%08x: %s (ordinal #%d)" % (ea, name, ordinal))
        # True -> Continue enumeration
        # False -> Stop enumeration
        return True
    ida_nalt.enum_import_names(i, imp_cb)
```

### ida_printSegment

```python
def ida_printSegment(curSeg):
  """
  print segment info
    Note: in IDA, segment == section
  """
  segName = curSeg.name
  # print("type(segName)=%s" % type(segName))
  segSelector = curSeg.sel
  segStartAddr = curSeg.start_ea
  segEndAddr = curSeg.end_ea
  print("Segment: [0x%X-0x%X] name=%s, selector=%s : seg=%s" % (segStartAddr, segEndAddr, segName, segSelector, curSeg))
```

### ida_getSegmentList

```python
def ida_getSegmentList():
  """
  get segment list
  """
  segList = []
  segNum = ida_segment.get_segm_qty()
  for segIdx in range(segNum):
    curSeg = ida_segment.getnseg(segIdx)
    # print("curSeg=%s" % curSeg)
    segList.append(curSeg)
    # ida_printSegment(curSeg)
  return segList
```

### ida_testGetSegment

```python
def ida_testGetSegment():
  """
  test get segment info
  """
  # textSeg = ida_segment.get_segm_by_name("__TEXT")
  # dataSeg = ida_segment.get_segm_by_name("__DATA")

  # ida_getSegmentList()

  # NAME___TEXT = "21"
  # NAME___TEXT = 21
  # NAME___TEXT = "__TEXT,__text"
  # NAME___TEXT = "__TEXT:__text"
  # NAME___TEXT = ".text"

  """
    __TEXT,__text
    __TEXT,__stubs
    __TEXT,__stub_helper
    __TEXT,__objc_stubs
    __TEXT,__const
    __TEXT,__objc_methname
    __TEXT,__cstring
    __TEXT,__swift5_typeref
    __TEXT,__swift5_protos
    __TEXT,__swift5_proto
    __TEXT,__swift5_types
    __TEXT,__objc_classname
    __TEXT,__objc_methtype
    __TEXT,__gcc_except_tab
    __TEXT,__ustring
    __TEXT,__unwind_info
    __TEXT,__eh_frame
    __TEXT,__oslogstring

    __DATA,__got
    __DATA,__la_symbol_ptr
    __DATA,__mod_init_func
    __DATA,__const
    __DATA,__cfstring
    __DATA,__objc_classlist
    __DATA,__objc_catlist
    __DATA,__objc_protolist
    __DATA,__objc_imageinfo
    __DATA,__objc_const
    __DATA,__objc_selrefs
    __DATA,__objc_protorefs
    __DATA,__objc_classrefs
    __DATA,__objc_superrefs
    __DATA,__objc_ivar
    __DATA,__objc_data
    __DATA,__data
    __DATA,__objc_stublist
    __DATA,__swift_hooks
    __DATA,__swift51_hooks
    __DATA,__s_async_hook
    __DATA,__swift56_hooks
    __DATA,__thread_vars
    __DATA,__thread_bss
    __DATA,__bss
    __DATA,__common
  """

  # __TEXT,__text
  NAME___text = "__text"
  textSeg = ida_segment.get_segm_by_name(NAME___text)
  print("textSeg: %s -> %s" % (NAME___text, textSeg))
  ida_printSegment(textSeg)

  # __TEXT,__objc_methname
  NAME___objc_methname = "__objc_methname"
  objcMethNameSeg = ida_segment.get_segm_by_name(NAME___objc_methname)
  print("objcMethNameSeg: %s -> %s" % (NAME___objc_methname, objcMethNameSeg))
  ida_printSegment(objcMethNameSeg)

  # __DATA,__got
  NAME___got = "__got"
  gotSeg = ida_segment.get_segm_by_name(NAME___got)
  print("gotSeg: %s -> %s" % (NAME___got, gotSeg))
  ida_printSegment(gotSeg)

  # __DATA,__data
  # NAME___DATA = "22"
  # NAME___DATA = 22
  NAME___DATA = "__data"
  dataSeg = ida_segment.get_segm_by_name(NAME___DATA)
  print("dataSeg: %s -> %s" % (NAME___DATA, dataSeg))
  ida_printSegment(dataSeg)

  # exist two one: __TEXT,__const / __DATA,__const
  NAME___const = "__const"
  constSeg = ida_segment.get_segm_by_name(NAME___const)
  print("constSeg: %s -> %s" % (NAME___const, constSeg))
  ida_printSegment(constSeg)
```

### ida_getDemangledName

```python
def ida_getDemangledName(origSymbolName):
  """
  use IDA to get demangled name for original symbol name
  """
  retName = origSymbolName
  # demangledName = idc.demangle_name(origSymbolName, idc.get_inf_attr(idc.INF_SHORT_DN))
  # https://hex-rays.com/products/ida/support/ida74_idapython_no_bc695_porting_guide.shtml
  demangledName = idc.demangle_name(origSymbolName, idc.get_inf_attr(idc.INF_SHORT_DEMNAMES))
  if demangledName:
    retName = demangledName

  # do extra post process:
  # remove/replace invalid char for non-objc function name
  isNotObjcFuncName = not isObjcFunctionName(retName)
  # print("isNotObjcFuncName=%s" % isNotObjcFuncName)
  if isNotObjcFuncName:
    retName = retName.replace("?", "")
    retName = retName.replace(" ", "_")
    retName = retName.replace("*", "_")
  # print("origSymbolName=%s -> retName=%s" % (origSymbolName, retName))
  return retName
```

### ida_getFunctionEndAddr

```python
def ida_getFunctionEndAddr(funcAddr):
  """
  get function end address
    Example:
      0x1023A2534 -> 0x1023A2540
  """
  funcAddrEnd = idc.get_func_attr(funcAddr, attr=idc.FUNCATTR_END)
  return funcAddrEnd
```

### ida_getFunctionSize

```python
def ida_getFunctionSize(funcAddr):
  """
  get function size
    Example:
      0x1023A2534 -> 12
  """
  funcAddrEnd = idc.get_func_attr(funcAddr, attr=idc.FUNCATTR_END)
  funcAddStart = idc.get_func_attr(funcAddr, attr=idc.FUNCATTR_START)
  funcSize = funcAddrEnd - funcAddStart
  return funcSize
```

### ida_getFunctionName

```python
def ida_getFunctionName(funcAddr):
  """
  get function name
    Exmaple:
      0x1023A2534 -> "sub_1023A2534"
      0xF9D260 -> "objc_msgSend$initWithKeyValueStore_namespace_binaryCoders_X22toX0_X23toX2_X24toX4_EF8C"
  """
  funcName = idc.get_func_name(funcAddr)
  return funcName
```

### ida_getName

```python
def ida_getName(curAddr):
  """
  get name
    Exmaple:
      0xF9D260 -> "_objc_msgSend$initWithKeyValueStore:namespace:binaryCoders:"
  """
  addrName = idc.get_name(curAddr)
  return addrName
```

### ida_getDisasmStr

```python
def ida_getDisasmStr(funcAddr):
  """
  get disasmemble string
    Exmaple:
      0x1023A2534 -> "MOV X5, X0"
  """
  # method 1: generate_disasm_line
  # disasmLine_forceCode = idc.generate_disasm_line(funcAddr, idc.GENDSM_FORCE_CODE)
  # print("disasmLine_forceCode: type=%s, val=%s" % (type(disasmLine_forceCode), disasmLine_forceCode))
  # disasmLine_multiLine = idc.generate_disasm_line(funcAddr, idc.GENDSM_MULTI_LINE)
  # print("disasmLine_multiLine: type=%s, val=%s" % (type(disasmLine_multiLine), disasmLine_multiLine))

  # method 2: GetDisasm
  disasmLine = idc.GetDisasm(funcAddr)
  # print("disasmLine: type=%s, val=%s" % (type(disasmLine), disasmLine))

  # post process
  # print("disasmLine=%s" % disasmLine)
  # "MOV             X4, X21" -> "MOV X4, X21"
  disasmLine = re.sub("\s+", " ", disasmLine)
  # print("disasmLine=%s" % disasmLine)
  return disasmLine
```

### ida_getFunctionAddrList

```python
def ida_getFunctionAddrList():
  """
  get function address list
  """
  functionIterator = idautils.Functions()
  functionAddrList = []
  for curFuncAddr in functionIterator:
    functionAddrList.append(curFuncAddr)
  return functionAddrList
```

### ida_rename

```python
def ida_rename(curAddr, newName, retryName=None):
  """
  rename <curAddr> to <newName>. if fail, retry with with <retryName> if not None
    Example:
      0x3B4E28, "X2toX21_X1toX20_X0toX19_4E28", "X2toX21_X1toX20_X0toX19_3B4E28" -> True, "X2toX21_X1toX20_X0toX19_4E28"
  """
  # print("curAddr=0x%X, newName=%s, retryName=%s" % (curAddr, newName, retryName))
  isRenameOk = False
  renamedName = None

  isOk = idc.set_name(curAddr, newName)
  # print("isOk=%s for [0x%X] -> %s" % (isOk, curAddr, newName))
  if isOk == 1:
    isRenameOk = True
    renamedName = newName
  else:
    if retryName:
      isOk = idc.set_name(curAddr, retryName)
      # print("isOk=%s for [0x%X] -> %s" % (isOk, curAddr, retryName))
      if isOk == 1:
        isRenameOk = True
        renamedName = retryName

  # print("isRenameOk=%s, renamedName=%s" % (isRenameOk, renamedName))
  return (isRenameOk, renamedName)
```

### ida_getCurrentFolder

```python
def ida_getCurrentFolder():
  """
  get current folder for IDA current opened binary file
    Example:
      -> /Users/crifan/dev/dev_root/iosReverse/WhatsApp/ipa/Payload/WhatsApp.app
      -> /Users/crifan/dev/dev_root/iosReverse/WhatsApp/ipa/Payload/WhatsApp.app/Frameworks/SharedModules.framework
  """
  curFolder = None
  inputFileFullPath = ida_nalt.get_input_file_path()
  # print("inputFileFullPath=%s" % inputFileFullPath)
  if inputFileFullPath.startswith("/var/containers/Bundle/Application"):
    # inputFileFullPath=/var/containers/Bundle/Application/2BE964D4-8DF0-4858-A06D-66CA8741ACDC/WhatsApp.app/WhatsApp
    # -> maybe IDA bug -> after debug settings, output iOS device path, but later no authority to write exported file to it
    # so need to avoid this case, change to output to PC side (Mac) current folder
    curFolder = "."
  else:
    curFolder = os.path.dirname(inputFileFullPath)
  # print("curFolder=%s" % curFolder)

  # debugInputPath = ida_nalt.dbg_get_input_path()
  # print("debugInputPath=%s" % debugInputPath)

  curFolder = os.path.abspath(curFolder)
  # print("curFolder=%s" % curFolder)
  # here work:
  # . -> /Users/crifan/dev/dev_root/iosReverse/WhatsApp/ipa/Payload/WhatsApp.app
  return curFolder
```

### isDefaultTypeForObjcMsgSendFunction

```python
def isDefaultTypeForObjcMsgSendFunction(funcAddr):
  """
  check is objc_msgSend$xxx function's default type "id(void *, const char *, ...)" or not
  eg:
    0xF3EF8C -> True
      note: funcType=id(void *, const char *, __int64, __int64, ...)
  """
  isDefType = False
  funcType = idc.get_type(funcAddr)
  # print("[0x%X] -> funcType=%s" % (funcAddr, funcType))
  if funcType:
    defaultTypeMatch = re.search("\.\.\.\)$", funcType)
    # print("defaultTypeMatch=%s" % defaultTypeMatch)
    isDefType = bool(defaultTypeMatch)
    # print("isDefType=%s" % isDefType)
  return isDefType
```

## 无需调用IDA的API的相关函数

### isDefaultSubFuncName

```python
def isDefaultSubFuncName(funcName):
  """
  check is default sub_XXX function or not from name
  eg:
    sub_F332C0 -> True, "F332C0"
  """
  isSub = False
  addressStr = None
  # subMatch = re.match("^sub_[0-9A-Za-z]+$", funcName)
  subMatch = re.match("^sub_(?P<addressStr>[0-9A-Fa-f]+)$", funcName)
  # print("subMatch=%s" % subMatch)
  if subMatch:
    isSub = True
    addressStr = subMatch.group("addressStr")
  return isSub, addressStr
```

### isReservedPrefix_loc

```python
def isReservedPrefix_loc(funcName):
  """
  check is reserved prefix loc_XXX name or not
  eg:
    loc_100007A2C -> True, "100007A2C"
  """
  isLoc = False
  addressStr = None
  locMatch = re.match("^loc_(?P<addressStr>[0-9A-Fa-f]+)$", funcName)
  # print("locMatch=%s" % locMatch)
  if locMatch:
    isLoc = True
    addressStr = locMatch.group("addressStr")
  return isLoc, addressStr
```

### isDefaultSubFunction

```python
def isDefaultSubFunction(curAddr):
  """
  check is default sub_XXX function or not from address
  """
  isDefSubFunc = False
  curFuncName  = ida_getFunctionName(curAddr)
  # print("curFuncName=%s" % curFuncName)
  if curFuncName:
    isDefSubFunc, subAddStr = isDefaultSubFuncName(curFuncName)
  return isDefSubFunc, curFuncName
```

### isObjcMsgSendFunction

```python
def isObjcMsgSendFunction(curAddr):
  """
  check is default sub_XXX function or not from address
  """
  isObjcMsgSend = False
  curFuncName  = ida_getFunctionName(curAddr)
  # print("curFuncName=%s" % curFuncName)
  if curFuncName:
    isObjcMsgSend, selectorStr = isObjcMsgSendFuncName(curFuncName)
  return isObjcMsgSend, selectorStr
```
