import std/[random, math, fenv, sequtils, strutils]

{.pragma: noCov, codegenDecl: "__attribute__((no_sanitize(\"coverage\"))) $# $#$#".}

# Experiment with custom mutator + reading zero bytes when the buffer is exhausted.
# Stress it with -max_len=16
# Notes: Seems to work well! Writing good mutators is hard, need to find ready made ones.
# Problem: All test cases size is same as maxlen, sizeIncreaseHint seems essential.

type
  GrowOrShrink = enum
    None,
    Grow, # Make `x` bigger.
    Shrink, # Make `x` smaller.

  Unstructured = object
    data: ptr UncheckedArray[byte]
    pos, len: int

var
  total = 0
  valid = 0
  step = 0

proc quitOrDebug() {.noreturn, importc: "abort", header: "<stdlib.h>", nodecl.}

proc initialize(): cint {.exportc: "LLVMFuzzerInitialize".} =
  {.emit: "N_CDECL(void, NimMain)(void); NimMain();".}

proc mutate(data: ptr UncheckedArray[byte], len, maxLen: int): int {.
    importc: "LLVMFuzzerMutate".}

template `+!`(p: pointer, s: int): untyped =
  cast[pointer](cast[ByteAddress](p) +% s)

proc mutate[T](v: var T; r: var Rand) =
  let size = mutate(cast[ptr UncheckedArray[byte]](addr v), sizeof(T), sizeof(T))
  zeroMem(v.addr +! size, sizeof(T) - size)

proc mutate[T](x: var seq[T], r: var Rand) =
  let oldLen = x.len
  while x.len > 0 and r.rand(bool):
    x.delete(rand(r, x.high))
  while r.rand(bool):
    let index = rand(r, x.len)
    var tmp = default(T)
    mutate(tmp, r)
    x.insert(tmp, index)
  if x.len != oldLen:
    return
  if x.len == 0:
    var tmp = default(T)
    mutate(tmp, r)
    x.add(tmp)
  else:
    let index = rand(r, x.high)
    mutate(x[index], r)

#proc mutate[T](x: var seq[T], r: var Rand) =
  #case r.rand(GrowOrShrink)
  #of GrowOrShrink.Grow:
    #if x.len >= 10: return # magic value!
    #let oldLen = x.len
    #x.setLen(r.rand(oldLen + 1..10))
    #for i in oldLen..<x.len: mutate(x[i], r)
  #of GrowOrShrink.Shrink:
    #if x.len == 0: return
    #x.shrink(r.rand(0..x.len - 1))
  #else: discard

proc toUnstructured(data: ptr UncheckedArray[byte]; len: int): Unstructured =
  Unstructured(data: data, pos: 0, len: len)

template `+!`(p: pointer, s: int): untyped =
  cast[pointer](cast[ByteAddress](p) +% s)

proc readData(x: var Unstructured, buffer: pointer, bufLen: int) =
  let n = min(bufLen, x.len - x.pos)
  copyMem(buffer, addr x.data[x.pos], n)
  zeroMem(buffer +! n, bufLen - n)
  inc(x.pos, n)

proc read[T](x: var Unstructured, result: var T) =
  readData(x, addr(result), sizeof(T))

proc readInt32(x: var Unstructured): int32 =
  read(x, result)

proc intInRange[T: SomeInteger](u: var Unstructured; x: Slice[T]): T =
  assert(x.a <= x.b, "intInRange requires a non-empty range")
  if x.a == x.b:
    return x.a
  let L = x.b.BiggestUInt - x.a.BiggestUInt
  read(u, result)
  var res = result.BiggestUInt
  # Avoid division by 0, in case |L + 1| results in overflow.
  if L != high(BiggestUInt):
    res = res mod (L + 1)
  result = cast[T](x.a.BiggestUInt + res)

proc initFromBin[T](dst: var seq[T]; x: var Unstructured) {.noCov.} =
  let len = readInt32(x) #x.intInRange(0'i32..10'i32) gives better results
  dst.setLen(len)
  if len > 0:
    let bLen = len * sizeof(T)
    readData(x, dst[0].addr, bLen)

proc writeData(x: var seq[byte], pos: var int, buffer: pointer, bufLen: int) =
  if bufLen <= 0:
    return
  if pos + bufLen > x.len:
    setLen(x, pos + bufLen)
  copyMem(addr(x[pos]), buffer, bufLen)
  inc(pos, bufLen)

proc write[T](x: var seq[byte], pos: var int, v: T) =
  writeData(x, pos, addr v, sizeof(v))

proc write(x: var seq[byte], pos: var int; v: seq[int32]) =
  write(x, pos, int32(v.len))
  if v.len > 0:
    writeData(x, pos, addr v[0], v.len * sizeof(int32))

proc fuzzMe(s: seq[int32]) =
  if s == @[0x11111111'i32, 0x22222222'i32, 0xdeadbeef'i32]:
    echo "PANIC!"; quitOrDebug()

proc printStats() {.noCov.} =
  inc step
  if step mod 100_000 == 0:
    echo "Valid inputs (%) ", formatFloat(valid/total*100)

proc testOneInput(data: ptr UncheckedArray[byte], len: int): cint {.
    exportc: "LLVMFuzzerTestOneInput", raises: [].} =
  result = 0
  if len < sizeof(int32): return
  var x: seq[int32] = @[]
  var u = toUnstructured(data, len)
  initFromBin(x, u)
  printStats()
  fuzzMe(x)

proc customMutator(data: ptr UncheckedArray[byte], len, maxLen: int, seed: int64): int {.
    exportc: "LLVMFuzzerCustomMutator".} =
  #if len < sizeof(int32): return
  var x: seq[int32] = @[]
  inc total
  var u = toUnstructured(data, len)
  initFromBin(x, u)
  var r = initRand(seed)
  mutate(x, r)
  var pos = 0
  var tmp = newSeq[byte](maxLen)
  write(tmp, pos, x)
  result = tmp.len
  if result <= maxLen:
    inc valid
    copyMem(data, addr tmp[0], result)
  else:
    result = len
