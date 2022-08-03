import std/[random, fenv, math]

# EXAMPLE FAILS TO MINIMISE THE CRASH in 6min! Can't crossover.

type
  FloatSeq = distinct seq[float]

  Unstructured = object
    data: ptr UncheckedArray[byte]
    r: Rand
    pos, len: int

proc quitOrDebug() {.noreturn, importc: "abort", header: "<stdlib.h>", nodecl.}

proc randFloat(r: var Rand): float =
  case r.rand(10)
  of 0:
    result = NaN
  of 1:
    result = minimumPositiveValue(float)
  of 2:
    result = maximumPositiveValue(float)
  of 3:
    result = -minimumPositiveValue(float)
  of 4:
    result = -maximumPositiveValue(float)
  of 5:
    result = epsilon(float)
  of 6:
    result = -epsilon(float)
  of 7:
    result = Inf
  of 8:
    result = -Inf
  of 9:
    result = 0
  else:
    result = r.rand(-1.0..1.0)

proc toUnstructured*(data: ptr UncheckedArray[byte]; len: int, seed: int64): Unstructured =
  Unstructured(data: data, pos: 0, len: len, r: initRand(seed))

proc readData(x: var Unstructured, buffer: pointer, bufLen: int): int =
  result = min(bufLen, x.len - x.pos)
  if result > 0:
    copyMem(buffer, addr x.data[x.pos], result)
    inc(x.pos, result)
  else:
    result = 0

proc read[T](x: var Unstructured, result: var T) =
  if readData(x, addr(result), sizeof(T)) != sizeof(T):
    quitOrDebug()

proc readInt64*(x: var Unstructured): int64 =
  read(x, result)

proc intInRange*[T: SomeInteger](u: var Unstructured; x: Slice[T]): T =
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

proc fromArbitrary(result: var FloatSeq; u: var Unstructured) =
  let len = intInRange(u, 0..10)
  seq[float](result).setLen(len)
  for i in 0..<len:
    seq[float](result)[i] = randFloat(u.r)

proc fromArbitrary[T](u: var Unstructured; t: typedesc[T]): T =
  fromArbitrary(result, u)

proc sum(x: openArray[float]): float =
  result = 0.0
  for b in items(x):
    result = if isNaN(b): result else: result + b

proc testOneInput(data: ptr UncheckedArray[byte], len: int): cint {.
    exportc: "LLVMFuzzerTestOneInput", raises: [].} =
  result = 0
  if len < sizeof(int64)*2: return
  var u = toUnstructured(data, len, len)
  let x = u.fromArbitrary(FloatSeq)
  let res = sum(seq[float](x))
  if isNaN(res): quitOrDebug()
