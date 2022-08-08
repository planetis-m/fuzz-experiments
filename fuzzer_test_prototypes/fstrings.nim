import random

{.pragma: noCov, codegenDecl: "__attribute__((no_sanitize(\"coverage\"))) $# $#$#".}

proc quitOrDebug() {.noreturn, importc: "abort", header: "<stdlib.h>", nodecl.}

proc initialize(): cint {.exportc: "LLVMFuzzerInitialize".} =
  {.emit: "N_CDECL(void, NimMain)(void); NimMain();".}

proc mutate*(data: ptr UncheckedArray[byte], len, maxLen: int): int {.
    importc: "LLVMFuzzerMutate".}

template `+!`(p: pointer, s: int): untyped =
  cast[pointer](cast[ByteAddress](p) +% s)

const
  RandomToDefaultRatio = 100

proc mutate[T](v: var T; r: var Rand) =
  let size = mutate(cast[ptr UncheckedArray[byte]](addr v), sizeof(T), sizeof(T))
  zeroMem(v.addr +! size, sizeof(T) - size)

proc mutateString(v: var string; sizeIncreaseHint: int; r: var Rand) =
  # Randomly return empty strings as LLVMFuzzerMutate does not produce them.
  if r.rand(0..20) == 0:
    v = ""
    return
  let oldSize = v.len
  v.setLen(max(1, oldSize + sizeIncreaseHint))
  v.setLen(mutate(cast[ptr UncheckedArray[byte]](addr v[0]), oldSize, v.len))

template repeatMutate(call: untyped) =
  if rand(r, RandomToDefaultRatio - 1) == 0:
    return
  var tmp = v
  for i in 1..10:
    call
    if v != tmp: return

proc mutate(v: var string; sizeIncreaseHint: Natural; r: var Rand) =
  repeatMutate(mutateString(v, sizeIncreaseHint, r))

type
  Unstructured = object
    data: ptr UncheckedArray[byte]
    pos, len: int

proc toUnstructured(data: ptr UncheckedArray[byte]; len: int): Unstructured =
  Unstructured(data: data, pos: 0, len: len)

proc readData(x: var Unstructured, buffer: pointer, bufLen: int): int =
  result = min(bufLen, x.len - x.pos)
  if result > 0:
    copyMem(buffer, addr x.data[x.pos], result)
    inc(x.pos, result)
  else:
    result = 0

proc read[T](x: var Unstructured, res: var T): bool =
  result = true
  if readData(x, addr(res), sizeof(T)) != sizeof(T):
    result = false

proc fromBin(dst: var string; x: var Unstructured): bool  =
  var len = 0'i32
  result = false
  if read(x, len):
    dst.setLen(len)
    result = true
    if len > 0:
      let bLen = len
      if readData(x, dst[0].addr, bLen) != bLen: result = false

proc writeData(x: var seq[byte], pos: var int, buffer: pointer, bufLen: int) =
  if bufLen <= 0:
    return
  if pos + bufLen > x.len:
    setLen(x, pos + bufLen)
  copyMem(addr(x[pos]), buffer, bufLen)
  inc(pos, bufLen)

proc write[T](x: var seq[byte], pos: var int, v: T) =
  writeData(x, pos, addr v, sizeof(v))

proc write(x: var seq[byte], pos: var int; v: string) =
  write(x, pos, int32(v.len))
  if v.len > 0:
    writeData(x, pos, addr v[0], v.len)

proc byteSize(x: string): int =
  result = sizeof(int32) + x.len

proc fuzzMe(s: string) =
  if s == "The one place that hasn't been corrupted by Capitalism.":
    echo "PANIC!"; quitOrDebug()

proc testOneInput(data: ptr UncheckedArray[byte], len: int): cint {.
    exportc: "LLVMFuzzerTestOneInput", raises: [].} =
  result = 0
  if len < sizeof(int32): return
  var x: string
  var u = toUnstructured(data, len)
  if fromBin(x, u):
    when defined(dumpFuzzInput): echo x
    fuzzMe(x)

proc customMutator*(data: ptr UncheckedArray[byte], len, maxLen: int, seed: int64): int {.
    exportc: "LLVMFuzzerCustomMutator".} =
  var x: string
  var u = toUnstructured(data, len)
  if not fromBin(x, u): return len
  var r = initRand(seed)
  mutate(x, maxLen - x.byteSize, r)
  var pos = 0
  var tmp = newSeq[byte](maxLen)
  write(tmp, pos, x)
  result = tmp.len
  if result <= maxLen:
    copyMem(data, addr tmp[0], result)
  else:
    result = len
