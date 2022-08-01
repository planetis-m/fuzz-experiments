import ".."/arbitrary, std/random

proc quitOrDebug() {.noreturn, importc: "abort", header: "<stdlib.h>", nodecl.}

proc fuzzMe(s: string; a, b, c: int32) =
  if a == 0xdeadbeef'i32 and b == 0x11111111'i32 and c == 0x22222222'i32:
    if s.len == 100: quitOrDebug()

proc initialize(): cint {.exportc: "LLVMFuzzerInitialize".} =
  {.emit: "N_CDECL(void, NimMain)(void); NimMain();".}

template inc(p: pointer, s: int) =
  p = cast[typeof(p)](cast[ByteAddress](p) +% s)

template randBool(r): bool = r.rand(99) != 0

proc testOneInput(data: ptr UncheckedArray[byte], len: int): cint {.
    exportc: "LLVMFuzzerTestOneInput", raises: [].} =
  result = 0
  if len < sizeof(int32) * 3 + 100: return
  var x = toUnstructured(data, len)
  #let s = x.readStr(100)
  #let s = x.readUtf8Str(100)
  #let seed = x.readInt[:int64]
  var r = initRand(len)
  var s = newStringOfCap(100)
  var keepGoing = r.randBool
  while keepGoing:
    s.add x.read[:char]
    keepGoing = r.randBool
  #let a = x.readInt[:int32]
  #let b = x.readInt[:int32]
  #let c = x.readInt[:int32]

  let a = x.read[:int32]
  let b = x.read[:int32]
  let c = x.read[:int32]

  #var data = data
  #if len < sizeof(int32) * 3 + 100: return
  #let s = newString(100)
  #copyMem(cstring(s), cast[cstring](data), s.len)
  #var a, b, c: int32
  #inc data, 100
  #copyMem(addr a, data, sizeof(a))
  #inc data, sizeof(a)
  #copyMem(addr b, data, sizeof(b))
  #inc data, sizeof(b)
  #copyMem(addr c, data, sizeof(c))
  fuzzMe(s, a, b, c)

#proc testOneInput(data: ptr UncheckedArray[byte], len: int): cint {.
    #exportc: "LLVMFuzzerTestOneInput".} =
  ##if len < 7: return
  ##var s = newString(6)
  ##copyMem(cstring(s), cast[cstring](data), s.len)

  #var x = toUnstructured(data, len)
  #let s = x.readRandStr(1000)

  #if s == "qwerty":
    #stderr.write("BINGO\n")
    #quitOrDebug()
