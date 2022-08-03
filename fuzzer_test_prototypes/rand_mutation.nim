# Test the Post-script idea in
# https://fitzgeraldnick.com/2019/09/04/combining-coverage-guided-and-generation-based-fuzzing.html
import std/[random, math, fenv]

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
    growOrShrink: GrowOrShrink): bool =
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

proc mutate(x: var float, r: var Rand,
    growOrShrink: GrowOrShrink): bool =
  let data = [
    -Inf,
    -maximumPositiveValue(float),
    -minimumPositiveValue(float),
    NaN,
    r.rand(-1.0..1.0),
    minimumPositiveValue(float),
    maximumPositiveValue(float),
    Inf
  ]
  case growOrShrink
  of GrowOrShrink.Grow:
    case classify(x)
    of fcInf: return false
    else: x = data[r.rand(1..high(data).int)]
    true
  of GrowOrShrink.Shrink:
    case classify(x)
    of fcNegInf: return false
    else: x = data[r.rand(0..high(data)-1)]
    true

proc toUnstructured(data: ptr UncheckedArray[byte]; len: int): Unstructured =
  Unstructured(data: data, pos: 0, len: len)

template `+!`(p: pointer, s: int): untyped =
  cast[pointer](cast[ByteAddress](p) +% s)

proc readData(x: var Unstructured, buffer: pointer, bufLen: int) =
  let n = min(bufLen, x.len - x.pos)
  copyMem(buffer, addr x.data[x.pos], n)
  zeroMem(buffer +! n, bufLen - n)
  inc(x.pos, n)

proc writeData(x: var Unstructured, buffer: pointer, bufLen: int) =
  if bufLen <= 0:
    return
  if x.pos + bufLen > x.len:
    quitOrDebug()
  copyMem(addr(x.data[x.pos]), buffer, bufLen)
  inc(x.pos, bufLen)

proc read[T](x: var Unstructured, result: var T) =
  readData(x, addr(result), sizeof(T))

proc readInt32(x: var Unstructured): int32 =
  read(x, result)

proc write[T](x: var Unstructured, v: T) =
  writeData(x, addr v, sizeof(v))

proc write(x: var Unstructured; v: seq[int32]) =
  write(x, int32(v.len))
  if v.len > 0:
    writeData(x, addr v[0], v.len * sizeof(int32))

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

proc initFromBin[T](dst: var seq[T]; x: var Unstructured) =
  let len = x.intInRange(0'i32..10'i32)
  dst.setLen(len)
  if len > 0:
    let bLen = len * sizeof(T)
    readData(x, dst[0].addr, bLen)

proc byteSize[T](x: seq[T]): int =
  result = sizeof(int32) + x.len * sizeof(T)

proc sum(x: openArray[float]): float =
  result = 0.0
  for b in items(x):
    result = if isNaN(b): result else: result + b

proc testOneInput(data: ptr UncheckedArray[byte], len: int): cint {.
    exportc: "LLVMFuzzerTestOneInput", raises: [].} =
  result = 0
  if len < sizeof(int32): return
  var x: seq[float]
  var u = toUnstructured(data, len)
  var r = initRand(len)
  initFromBin(x, u)
  discard mutate(x, r, Shrink)
  let res = sum(x)
  if isNaN(res): echo "PANIC!"; quitOrDebug()
