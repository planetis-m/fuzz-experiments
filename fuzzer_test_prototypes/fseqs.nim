import random

# Experiment with calling LibFuzzer's mutate method on variable-sized data (bigger than bytes).
# Notes: Seems to work fine, might be a decent solution to the whole mutators mess.
# Managed to make them composable.

{.pragma: noCoverage, codegenDecl: "__attribute__((no_sanitize(\"coverage\"))) $# $#$#".}

proc quitOrDebug() {.noreturn, importc: "abort", header: "<stdlib.h>", nodecl.}

proc fuzzMe(s: seq[int32]) =
  if s == @[0x11111111'i32, 0x22222222'i32, 0xdeadbeef'i32]:
    echo "PANIC!"; quitOrDebug()

type
  Unstructured = object
    data: ptr UncheckedArray[byte]
    pos, len: int

proc toUnstructured*(data: ptr UncheckedArray[byte]; len: int): Unstructured {.noCoverage.} =
  Unstructured(data: data, pos: 0, len: len)

proc setPosition(x: var Unstructured, pos: int) =
  x.pos = clamp(pos, 0, x.len)

proc readData(x: var Unstructured, buffer: pointer, bufLen: int): int =
  result = min(bufLen, x.len - x.pos)
  if result > 0:
    copyMem(buffer, addr x.data[x.pos], result)
    inc(x.pos, result)
  else:
    result = 0

proc writeData(x: var Unstructured, buffer: pointer, bufLen: int) =
  if bufLen <= 0:
    return
  if x.pos + bufLen > x.len:
    quitOrDebug()
  copyMem(addr(x.data[x.pos]), buffer, bufLen)
  inc(x.pos, bufLen)

proc read[T](x: var Unstructured, result: var T) =
  if readData(x, addr(result), sizeof(T)) != sizeof(T):
    quitOrDebug()

proc readInt32(x: var Unstructured): int32 =
  read(x, result)

proc write[T](x: var Unstructured, v: T) =
  writeData(x, addr v, sizeof(v))

proc write(x: var Unstructured; v: seq[int32]) =
  write(x, int32(v.len))
  if v.len > 0:
    writeData(x, addr v[0], v.len * sizeof(int32))

proc initFromBin(dst: var seq[int32]; x: var Unstructured) {.noCoverage.} =
  let len = int x.readInt32()
  dst.setLen(len)
  if len > 0:
    let bLen = len * sizeof(int32)
    if readData(x, dst[0].addr, bLen) != bLen:
      quitOrDebug()

proc byteSize(x: seq[int32]): int =
  result = sizeof(int32) + x.len * sizeof(int32)

proc testOneInput(data: ptr UncheckedArray[byte], len: int): cint {.
    exportc: "LLVMFuzzerTestOneInput", raises: [].} =
  result = 0
  if len < sizeof(int32): return
  var x: seq[int32]
  var u = toUnstructured(data, len)
  initFromBin(x, u)
  when defined(dumpFuzzInput): echo x
  fuzzMe(x)

proc initialize(): cint {.exportc: "LLVMFuzzerInitialize".} =
  {.emit: "N_CDECL(void, NimMain)(void); NimMain();".}

proc mutate*(data: ptr UncheckedArray[byte], len, maxLen: int): int {.
    importc: "LLVMFuzzerMutate".}

template `+!`(p: pointer, s: int): untyped =
  cast[pointer](cast[ByteAddress](p) +% s)

const
  RandomToDefaultRatio = 100

proc mutateValue[T](value: T; sizeIncreaseHint: int; r: var Rand): T =
  result = value
  let size = mutate(cast[ptr UncheckedArray[byte]](addr result), sizeof(T), sizeof(T))
  zeroMem(result.addr +! size, sizeof(T) - size)

proc mutateValue[T](value: sink seq[T]; sizeIncreaseHint: int; r: var Rand): seq[T] =
  result = value
  while result.len > 0 and r.rand(bool):
    result.delete(rand(r, high(result)))
  while sizeIncreaseHint > 0 and result.byteSize < sizeIncreaseHint and r.rand(bool):
    let index = rand(r, len(result))
    result.insert(mutateValue(default(T), sizeIncreaseHint, r), index)
  if result != value:
    return result
  if result.len == 0:
    result.add(mutateValue(default(T), sizeIncreaseHint, r))
    return result
  else:
    let index = rand(r, high(result))
    result[index] = mutateValue(result[index], sizeIncreaseHint, r)

proc mutateValue(value: sink seq[int32]; sizeIncreaseHint: int; r: var Rand): seq[int32] =
  if r.rand(0..20) == 0:
    return @[]
  result = value
  var newSize = value.len * sizeof(int32) + sizeIncreaseHint
  result.setLen(max(1, newSize div sizeof(int32)))
  newSize = mutate(cast[ptr UncheckedArray[byte]](addr result[0]), value.len * sizeof(int32), newSize)
  result.setLen(newSize div sizeof(int32))

template repeatMutate(call: untyped) =
  if rand(r, RandomToDefaultRatio - 1) == 0:
    return
  var tmp = value
  for i in 1..10:
    value = call
    if value != tmp: return

proc mutate(value: var seq[int32]; sizeIncreaseHint: Natural; r: var Rand) =
  repeatMutate(mutateValue(value, sizeIncreaseHint, r))

proc customMutator*(data: ptr UncheckedArray[byte], len, maxLen: int, seed: int64): int {.
    exportc: "LLVMFuzzerCustomMutator".} =
  var x: seq[int32]
  if len >= sizeof(int32):
    var u = toUnstructured(data, len)
    initFromBin(x, u)
  var r = initRand(seed)
  mutate(x, maxLen - x.byteSize, r)
  #x = mutate(x, maxLen - x.byteSize, r)
  result = x.byteSize
  if result <= maxLen:
    var u = toUnstructured(data, maxLen)
    u.write(x)
  else:
    result = len

proc customCrossOver(data1: ptr UncheckedArray[byte], len1: int,
    data2: ptr UncheckedArray[byte], len2: int, res: ptr UncheckedArray[byte],
    maxResLen: int, seed: int64): int {.
    exportc: "LLVMFuzzerCustomCrossOver".} =

  var copy1: seq[int32]
  if len1 >= sizeof(int32):
    var readStr1 = toUnstructured(data1, len1)
    initFromBin(copy1, readStr1)

  var copy2: seq[int32]
  if len2 >= sizeof(int32):
    var readStr2 = toUnstructured(data2, len2)
    initFromBin(copy2, readStr2)

  let len = min(copy1.len, min(copy2.len, (maxResLen - sizeof(int32)) div sizeof(int32)))
  if len == 0: return
  var buf = newSeq[int32](len)

  var r = initRand(seed)
  for i in 0 ..< buf.len:
    buf[i] = if r.rand(bool): copy1[i]
             else: copy2[i]

  result = buf.byteSize
  if result <= maxResLen:
    var writeStr = toUnstructured(res, maxResLen)
    writeStr.write(buf)
  else:
    result = len
