import random

proc quitOrDebug() {.noreturn, importc: "abort", header: "<stdlib.h>", nodecl.}

proc fuzzMe(s: seq[int32]) =
  if s == @[0x11111111'i32, 0x22222222'i32, 0xdeadbeef'i32]:
    echo "PANIC!"; quitOrDebug()

type
  Unstructured = object
    data: ptr UncheckedArray[byte]
    pos, len: int

proc toUnstructured*(data: ptr UncheckedArray[byte]; len: int): Unstructured =
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

proc readInt32*(x: var Unstructured): int32 =
  read(x, result)

proc write[T](x: var Unstructured, v: T) =
  writeData(x, addr v, sizeof(v))

proc write(x: var Unstructured; v: seq[int32]) =
  write(x, int32(v.len))
  if v.len > 0:
    writeData(x, addr v[0], v.len * sizeof(int32))

proc initFromBin(dst: var seq[int32]; x: var Unstructured) =
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
  var copy: seq[int32]
  var readStr = toUnstructured(data, len)
  initFromBin(copy, readStr)
  #echo copy
  fuzzMe(copy)

proc initialize(): cint {.exportc: "LLVMFuzzerInitialize".} =
  {.emit: "N_CDECL(void, NimMain)(void); NimMain();".}

proc mutate*(data: ptr UncheckedArray[byte], len, maxLen: int): int {.
    importc: "LLVMFuzzerMutate".}

template `+!`(p: pointer, s: int): untyped =
  cast[pointer](cast[ByteAddress](p) +% s)

proc mutate[T](v: T; r: var Rand): T =
  result = v
  let size = mutate(cast[ptr UncheckedArray[byte]](addr result), sizeof(T), sizeof(T))
  zeroMem(result.addr +! size, sizeof(T) - size)

proc randBool(r: var Rand; n = 2): bool {.inline.} =
  # Return true with probability about 1-of-n.
  r.rand(n-1) == 0

proc mutate(value: sink seq[int32]; sizeIncreaseHint: int; r: var Rand): seq[int32] =
  result = value
  while result.len > 0 and randBool(r):
    result.delete(rand(r, high(result)))
  while sizeIncreaseHint > 0 and result.byteSize < sizeIncreaseHint and randBool(r):
    let index = rand(r, len(result))
    result.insert(mutate(default(int32), r), index)
  if result != value:
    return result
  if result.len == 0:
    result.add(mutate(default(int32), r))
    return result
  else:
    let index = rand(r, high(result))
    result[index] = mutate(result[index], r)

proc customMutator*(data: ptr UncheckedArray[byte], len, maxLen: int, seed: int64): int {.
    exportc: "LLVMFuzzerCustomMutator".} =
  var copy: seq[int32]
  if len >= sizeof(int32):
    var readStr = toUnstructured(data, len)
    initFromBin(copy, readStr)
  var gen = initRand(seed)
  let value = mutate(copy, maxLen - byteSize(copy), gen)
  result = value.byteSize
  if result <= maxLen:
    var writeStr = toUnstructured(data, maxLen)
    writeStr.write(value)
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

  var gen = initRand(seed)
  for i in 0 ..< buf.len:
    buf[i] = if randBool(gen): copy1[i]
             else: copy2[i]

  result = buf.byteSize
  if result <= maxResLen:
    var writeStr = toUnstructured(res, maxResLen)
    writeStr.write(buf)
  else:
    result = len
