import std/random, strutils

proc quitOrDebug() {.noreturn, importc: "abort", header: "<stdlib.h>", nodecl.}

proc fuzzMe(s: string) =
  if s.len == 16 and s == "00000000DEADBEEF": quitOrDebug()

proc initialize(): cint {.exportc: "LLVMFuzzerInitialize".} =
  {.emit: "N_CDECL(void, NimMain)(void); NimMain();".}

proc mutate(data: ptr UncheckedArray[byte], len, maxLen: int): int {.
    importc: "LLVMFuzzerMutate".}

proc testOneInput(data: ptr UncheckedArray[byte], len: int): cint {.
    exportc: "LLVMFuzzerTestOneInput", raises: [].} =
  result = 0
  if len < 16: return
  var s = ""
  s.setLen(len)
  copyMem(cstring(s), cast[cstring](data), len)
  fuzzMe(s)

proc customMutator*(data: ptr UncheckedArray[byte], len, maxLen: int, seed: int64): int {.
    exportc: "LLVMFuzzerCustomMutator".} =
  var a = 0xff'i32
  if len < sizeof(int32):
    copyMem(addr a, data, sizeof(a))
  result = mutate(cast[ptr UncheckedArray[byte]](addr a), sizeof(a), sizeof(a))
  var s = toHex(a)
  copyMem(data, addr a, sizeof(a))
