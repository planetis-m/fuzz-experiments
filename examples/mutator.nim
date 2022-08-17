import std/random, common, sampler
from typetraits import distinctBase

proc initialize(): cint {.exportc: "LLVMFuzzerInitialize".} =
  {.emit: "N_CDECL(void, NimMain)(void); NimMain();".}

when not defined(fuzzSa):
  proc mutate*(data: ptr UncheckedArray[byte], len, maxLen: int): int {.
      importc: "LLVMFuzzerMutate".}

template `+!`(p: pointer, s: int): untyped =
  cast[pointer](cast[ByteAddress](p) +% s)

const
  RandomToDefaultRatio* = 100
  DefaultMutateWeight* = 1000000

proc mutate*[T: SomeNumber](value: var T; sizeIncreaseHint: Natural; r: var Rand)
proc mutate*[T](value: var seq[T]; sizeIncreaseHint: Natural; r: var Rand)
proc mutate*[T: object](value: var T; sizeIncreaseHint: Natural; r: var Rand)

proc flipBit*(bytes: ptr UncheckedArray[byte]; len: int; r: var Rand) =
  # Flips random bit in the buffer.
  let bit = rand(r, len * 8 - 1)
  bytes[bit div 8] = bytes[bit div 8] xor (1'u8 shl (bit mod 8))

proc flipBit*[T](value: T; r: var Rand): T =
  # Flips random bit in the value.
  result = value
  flipBit(cast[ptr UncheckedArray[byte]](addr result), sizeof(T), r)

when not defined(fuzzSa):
  proc mutateValue*[T](value: T; r: var Rand): T =
    result = value
    let size = mutate(cast[ptr UncheckedArray[byte]](addr result), sizeof(T), sizeof(T))
    zeroMem(result.addr +! size, sizeof(T) - size)
else:
  proc mutateValue*[T](value: T; r: var Rand): T =
    flipBit(value, r)

proc mutateEnum*(index, itemCount: int; r: var Rand): int =
  if itemCount <= 1: 0
  else: (index + 1 + r.rand(itemCount - 1)) mod itemCount

proc mutateSeq*[T](value: sink seq[T]; userMax: Natural; sizeIncreaseHint: int;
    r: var Rand): seq[T] =
  template newInput: untyped =
    (var tmp = default(T); mutate(tmp, sizeIncreaseHint, r); tmp)
  result = value
  while result.len > 0 and r.rand(bool):
    result.delete(rand(r, result.high))
  while result.len < userMax and sizeIncreaseHint > 0 and
      result.byteSize < sizeIncreaseHint and r.rand(bool):
    let index = rand(r, result.len)
    result.insert(newInput(), index)
  # There is a chance we delete and then insert the same item.
  if result != value:
    return result
  if result.len == 0:
    result.add(newInput)
    return result
  else:
    let index = rand(r, result.high)
    mutate(result[index], sizeIncreaseHint, r)

proc sample*[T: distinct](x: T, depth: int, s: var Sampler; r: var Rand; res: var int) =
  sample(x.distinctBase, depth, s, r, res)

proc sample*[T: SomeNumber](x: T, depth: int, s: var Sampler; r: var Rand; res: var int) =
  inc res
  test(s, r, DefaultMutateWeight, res)

proc sample*[T](x: seq[T], depth: int, s: var Sampler; r: var Rand; res: var int) =
  inc res
  test(s, r, DefaultMutateWeight, res)

proc sample*[T: object](x: T, depth: int, s: var Sampler; r: var Rand; res: var int) =
  for v in fields(x):
    sample(v, depth, s, r, res)

proc pick*[T: distinct](x: var T, depth: int, sizeIncreaseHint: int; r: var Rand; res: var int) =
  pick(x.distinctBase, depth, sizeIncreaseHint, r, res)

template pickMutate(call: untyped) =
  if res > 0:
    dec res
    if res == 0:
      call

proc pick*[T: SomeNumber](x: var T, depth: int, sizeIncreaseHint: int; r: var Rand; res: var int) =
  pickMutate(mutate(x, sizeIncreaseHint, r))

proc pick*[T](x: var seq[T], depth: int, sizeIncreaseHint: int; r: var Rand; res: var int) =
  pickMutate(mutate(x, sizeIncreaseHint, r))

proc pick*[T: object](x: var T, depth: int, sizeIncreaseHint: int; r: var Rand; res: var int) =
  for v in fields(x):
    pick(v, depth, sizeIncreaseHint, r, res)

proc mutateObj*[T: object](value: var T; sizeIncreaseHint: int;
    r: var Rand) =
  var res = 0
  var s: Sampler[int]
  sample(value, 0, s, r, res)
  res = s.selected
  pick(value, 0, sizeIncreaseHint, r, res)

template repeatMutate*(call: untyped) =
  if rand(r, RandomToDefaultRatio - 1) == 0:
    #reset(value)
    return
  var tmp = value
  for i in 1..10:
    value = call
    if value != tmp: return

proc mutate*[T: SomeNumber](value: var T; sizeIncreaseHint: Natural; r: var Rand) =
  repeatMutate(mutateValue(value, r))

proc mutate*[T](value: var seq[T]; sizeIncreaseHint: Natural; r: var Rand) =
  repeatMutate(mutateSeq(value, high(Natural), sizeIncreaseHint, r))

proc mutate*[T: object](value: var T; sizeIncreaseHint: Natural; r: var Rand) =
  if rand(r, RandomToDefaultRatio - 1) == 0:
    #reset(value)
    return
  mutateObj(value, sizeIncreaseHint, r)

template defaultMutator*[T](target: proc (x: T) {.nimcall, noSideEffect.}) =
  {.pragma: nocov, codegenDecl: "__attribute__((no_sanitize(\"coverage\"))) $# $#$#".}
  {.pragma: nosan, codegenDecl: "__attribute__((disable_sanitizer_instrumentation)) $# $#$#".}

  var
    buffer: seq[byte] = @[0xf1'u8]
    cached: T

  proc input(x: var T; data: openArray[byte]): lent T {.nocov, nosan.} =
    if equals(data, buffer):
      result = cached
    else:
      var pos = 1
      fromData(data, pos, x)
      result = x

  proc quitWithMsg() {.noinline, noreturn, nosan, nocov.} =
    quit("Fuzzer quited with unhandled exception: " & getCurrentExceptionMsg())

  proc testOneInput(data: ptr UncheckedArray[byte], len: int): cint {.
      exportc: "LLVMFuzzerTestOneInput", raises: [].} =
    result = 0
    if len > 1: # ignore '\n' passed by LibFuzzer.
      var x: T
      try:
        target(input(x, toOpenArray(data, 0, len-1)))
      except:
        quitWithMsg()

  proc customMutator(data: ptr UncheckedArray[byte], len, maxLen: int, seed: int64): int {.
      exportc: "LLVMFuzzerCustomMutator", nosan.} =
    var r = initRand(seed)
    var x: T
    var y {.cursor.} = input(x, toOpenArray(data, 0, len-1))
    mutate(y, maxLen-y.byteSize, r)
    result = y.byteSize+1 # +1 for the skipped byte
    if result <= maxLen:
      setLen(buffer, result)
      var pos = 1
      toData(buffer, pos, y)
      assert pos == result
      copyMem(data, addr buffer[0], result)
      cached = move y
    else: result = len
