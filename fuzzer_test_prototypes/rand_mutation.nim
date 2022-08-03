# Test the Post-script idea in
# https://fitzgeraldnick.com/2019/09/04/combining-coverage-guided-and-generation-based-fuzzing.html
import std/[random, math, fenv, sequtils]

{.pragma: noCov, codegenDecl: "__attribute__((no_sanitize(\"coverage\"))) $# $#$#".}

type
  GrowOrShrink = enum
    Grow, # Make `x` bigger.
    Shrink, # Make `x` smaller.

  Unstructured = object
    data: ptr UncheckedArray[byte]
    pos, len: int

proc quitOrDebug() {.noreturn, importc: "abort", header: "<stdlib.h>", nodecl.}

proc initialize(): cint {.exportc: "LLVMFuzzerInitialize".} =
  {.emit: "N_CDECL(void, NimMain)(void); NimMain();".}

#proc mutate[T](x: var T, r: var Rand,
    #growOrShrink: GrowOrShrink): bool
  ## Mutate `self` with a random mutation to be either bigger
  ## or smaller. Return `true` if successfully mutated, `false`
  ## if `self` can't get any bigger/smaller.

# Example implementation for `int64`.
proc mutate(x: var int64, r: var Rand,
    growOrShrink: GrowOrShrink): bool =
  case growOrShrink
  of GrowOrShrink.Grow:
    if x == high(int64): return false
    x = r.rand(x + 1..high(int64))
    true
  of GrowOrShrink.Shrink:
    if x == 0: return false
    x = r.rand(0'i64..x - 1)
    true

proc mutate[T](x: var seq[T], r: var Rand,
    growOrShrink: GrowOrShrink): bool {.noCov.} =
  case growOrShrink
  of GrowOrShrink.Grow:
    if x.len >= 10: return false
    x.grow(r.rand(x.len + 1..10), default(T))
    result = true
    for y in mitems(x):
      result = result and mutate(y, r, Grow)
  of GrowOrShrink.Shrink:
    if x.len == 0: return false
    x.shrink(r.rand(0..x.len - 1))
    result = true
    for y in mitems(x):
      result = result and mutate(y, r, Shrink)

#proc mutate(x: var float, r: var Rand,
    #growOrShrink: GrowOrShrink): bool =
  #let data = [
    #minimumPositiveValue(float),
    #maximumPositiveValue(float),
    #-minimumPositiveValue(float),
    #-maximumPositiveValue(float),
    #-epsilon(float),
    #epsilon(float),
    #-Inf,
    #Inf,
    #0,
    #r.rand(-1.0..1.0),
  #]
  #var tmp: array[data.len, float]
  #case growOrShrink
  #of GrowOrShrink.Grow:
    #var i = 0
    #for y in data.items:
      #if y > x: tmp[i] = y; inc i
    #x = if i > 0: tmp[r.rand(0..<i)] else: NaN
    #true
  #of GrowOrShrink.Shrink:
    #var i = 0
    #for y in data.items:
      #if y < x: tmp[i] = y; inc i
    #x = if i > 0: tmp[r.rand(0..<i)] else: NaN
    #true

proc mutate(x: var float, r: var Rand,
    growOrShrink: GrowOrShrink): bool =
  result = true
  case r.rand(10)
  of 0:
    x = NaN
  of 1:
    x = minimumPositiveValue(float)
  of 2:
    x = maximumPositiveValue(float)
  of 3:
    x = -minimumPositiveValue(float)
  of 4:
    x = -maximumPositiveValue(float)
  of 5:
    x = epsilon(float)
  of 6:
    x = -epsilon(float)
  of 7:
    x = Inf
  of 8:
    x = -Inf
  of 9:
    x = 0
  else:
    x = r.rand(-1.0..1.0)

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
  let len = x.intInRange(0'i32..10'i32)
  dst.setLen(len)
  if len > 0:
    let bLen = len * sizeof(T)
    readData(x, dst[0].addr, bLen)

proc sum(x: openArray[float]): float =
  result = 0.0
  for b in items(x):
    result = if isNaN(b): result else: result + b

proc initRandom(seed: int64): Rand {.noCov.} = initRand(seed)

proc testOneInput(data: ptr UncheckedArray[byte], len: int): cint {.
    exportc: "LLVMFuzzerTestOneInput", raises: [].} =
  result = 0
  if len < sizeof(int32): return
  var x: seq[float] = @[]
  var u = toUnstructured(data, len)
  var r = initRandom(len)
  initFromBin(x, u)
  discard mutate(x, r, Shrink)
  if x.len == 0: return
  let res = sum(x)
  if isNaN(res): echo "PANIC!"; quitOrDebug()
