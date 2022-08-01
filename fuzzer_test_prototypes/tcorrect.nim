import std/random, strutils

proc quitOrDebug() {.noreturn, importc: "abort", header: "<stdlib.h>", nodecl.}

proc fuzzMe(a: int32) =
  let s = toHex(a)
  if s.len == 16 and s == "00000000DEADBEEF": quitOrDebug()

proc initialize(): cint {.exportc: "LLVMFuzzerInitialize".} =
  {.emit: "N_CDECL(void, NimMain)(void); NimMain();".}

proc mutate(data: ptr UncheckedArray[byte], len, maxLen: int): int {.
    importc: "LLVMFuzzerMutate".}

proc testOneInput(data: ptr UncheckedArray[byte], len: int): cint {.
    exportc: "LLVMFuzzerTestOneInput", raises: [].} =
  result = 0
  if len < sizeof(int32): return
  var a: int32
  copyMem(addr a, data, sizeof(a))
  fuzzMe(a)

proc customMutator*(data: ptr UncheckedArray[byte], len, maxLen: int, seed: int64): int {.
    exportc: "LLVMFuzzerCustomMutator".} =
  var a = 0xff'i32
  if len < sizeof(int32):
    copyMem(addr a, data, sizeof(a))
  var s = toHex(a)
  let oldLen = s.len
  s.setLen(2*oldLen)
  discard mutate(cast[ptr UncheckedArray[byte]](cstring(s)), oldLen, s.len)
  a = cast[int32](parseHexInt(s))
  copyMem(data, addr a, sizeof(a))
