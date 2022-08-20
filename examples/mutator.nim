import std/random, common, sampler, macros
from typetraits import distinctBase, supportsCopyMem

template fuzzMax*(len: Positive) {.pragma.}
template fuzzIgnore* {.pragma.}

when not defined(fuzzSa):
  proc initialize(): cint {.exportc: "LLVMFuzzerInitialize".} =
    {.emit: "N_CDECL(void, NimMain)(void); NimMain();".}

  proc mutate*(data: ptr UncheckedArray[byte], len, maxLen: int): int {.
      importc: "LLVMFuzzerMutate".}

template `+!`(p: pointer, s: int): untyped =
  cast[pointer](cast[ByteAddress](p) +% s)

const
  RandomToDefaultRatio* = 100
  DefaultMutateWeight* = 1000000
  MaxInitializeDepth* = 200

proc mutate*[T: SomeNumber](value: var T; sizeIncreaseHint: int; r: var Rand)
proc mutate*[T](value: var seq[T]; sizeIncreaseHint: int; r: var Rand)

proc runMutator*[T: SomeNumber](x: var T; sizeIncreaseHint: int; r: var Rand)
proc runMutator*[T](x: var seq[T]; sizeIncreaseHint: int; r: var Rand)
proc runMutator*[T: object](x: var T; sizeIncreaseHint: int; r: var Rand)

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
    (var tmp = default(T); runMutator(tmp, sizeIncreaseHint, r); tmp)
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
    runMutator(result[index], sizeIncreaseHint, r)

template sampleTest*(call: untyped) =
  inc res
  call

proc sample*[T: distinct](x: T, depth: int, s: var Sampler; r: var Rand; res: var int) =
  when compiles(mutate(x, 0, r)):
    sampleTest(test(x, r, DefaultMutateWeight, res))
  else:
    sample(x.distinctBase, depth, s, r, res)

proc sample*[T: SomeNumber](x: T, depth: int, s: var Sampler; r: var Rand; res: var int) =
  sampleTest(test(s, r, DefaultMutateWeight, res))

proc sample*[T](x: seq[T], depth: int, s: var Sampler; r: var Rand; res: var int) =
  sampleTest(test(s, r, DefaultMutateWeight, res))

proc sample*[T: object](x: T, depth: int, s: var Sampler; r: var Rand; res: var int) =
  when compiles(mutate(x, 0, r)):
    sampleTest(test(x, r, DefaultMutateWeight, res))
  else:
    for v in fields(x):
      sample(v, depth, s, r, res)

template pickMutate*(call: untyped) =
  if res > 0:
    dec res
    if res == 0:
      call

proc pick*[T: distinct](x: var T, depth: int, sizeIncreaseHint: int; r: var Rand; res: var int) =
  when compiles(mutate(x, sizeIncreaseHint, r)):
    pickMutate(mutate(x, sizeIncreaseHint, r))
  else:
    pick(x.distinctBase, depth, sizeIncreaseHint, r, res)

proc pick*[T: SomeNumber](x: var T, depth: int, sizeIncreaseHint: int; r: var Rand; res: var int) =
  pickMutate(mutate(x, sizeIncreaseHint, r))

proc pick*[T](x: var seq[T], depth: int, sizeIncreaseHint: int; r: var Rand; res: var int) =
  pickMutate(mutate(x, sizeIncreaseHint, r))

proc pick*[T: object](x: var T, depth: int, sizeIncreaseHint: int; r: var Rand; res: var int) =
  when compiles(mutate(x, sizeIncreaseHint, r)):
    pickMutate(mutate(x, sizeIncreaseHint, r))
  else:
    for v in fields(x):
      pick(v, depth, sizeIncreaseHint, r, res)

proc runMutator*[T: distinct](x: var T; sizeIncreaseHint: int; r: var Rand) =
  when compiles(mutate(x, sizeIncreaseHint, r)):
    if rand(r, RandomToDefaultRatio - 1) == 0:
      reset(x)
    else:
      mutate(x, sizeIncreaseHint, r)
  else: runMutator(x.distinctBase, sizeIncreaseHint, r)

proc runMutator*[T: SomeNumber](x: var T; sizeIncreaseHint: int; r: var Rand) =
  if rand(r, RandomToDefaultRatio - 1) == 0:
    reset(x)
  else:
    mutate(x, sizeIncreaseHint, r)

proc runMutator*[T](x: var seq[T]; sizeIncreaseHint: int; r: var Rand) =
  if rand(r, RandomToDefaultRatio - 1) == 0:
    reset(x)
  else:
    mutate(x, sizeIncreaseHint, r)

proc runMutator*[T: object](x: var T; sizeIncreaseHint: int;
    r: var Rand) =
  if rand(r, RandomToDefaultRatio - 1) == 0:
    reset(x)
  else:
    when compiles(mutate(x, sizeIncreaseHint, r)):
      mutate(x, sizeIncreaseHint, r)
    else:
      var res = 0
      var s: Sampler[int]
      sample(x, 0, s, r, res)
      res = s.selected
      pick(x, 0, sizeIncreaseHint, r, res)

template repeatMutate*(call: untyped) =
  var tmp = value
  for i in 1..10:
    value = call
    if value != tmp: return

proc mutate*[T: SomeNumber](value: var T; sizeIncreaseHint: int; r: var Rand) =
  repeatMutate(mutateValue(value, r))

proc mutate*[T](value: var seq[T]; sizeIncreaseHint: int; r: var Rand) =
  repeatMutate(mutateSeq(value, high(Natural), sizeIncreaseHint, r))

proc runPostProcessor*[T: SomeNumber](x: var T, depth: int; r: var Rand)
proc runPostProcessor*[T](x: var seq[T], depth: int; r: var Rand)
proc runPostProcessor*[T: object](x: var T, depth: int; r: var Rand)

proc runPostProcessor*[T: distinct](x: var T, depth: int; r: var Rand) =
  when compiles(postProcess(x, r)):
    if depth < 0:
      when not supportsCopyMem(T): reset(x)
    else: postProcess(x, r)
  else:
    runPostProcessor(x.distinctBase, depth-1, r)

proc runPostProcessor*[T: SomeNumber](x: var T, depth: int; r: var Rand) =
  if depth >= 0:
    when compiles(postProcess(x, r)):
      postProcess(x, r)

proc runPostProcessor*[T](x: var seq[T], depth: int; r: var Rand) =
  if depth < 0:
    reset(x)
  else:
    when compiles(postProcess(x, r)):
      postProcess(x, r)
    else:
      for i in 0..<x.len:
        runPostProcessor(x[i], depth-1, r)

proc runPostProcessor*[T: object](x: var T, depth: int; r: var Rand) =
  if depth < 0:
    when not supportsCopyMem(T): reset(x)
  else:
    when compiles(postProcess(x, r)):
      postProcess(x, r)
    else:
      for v in fields(x):
        runPostProcessor(v, depth-1, r)

proc myMutator[T](x: var T; sizeIncreaseHint: Natural; r: var Rand) {.nimcall.} =
  runMutator(x, sizeIncreaseHint, r)
  runPostProcessor(x, MaxInitializeDepth, r)

template mutatorImpl(target, mutator, typ: untyped) =
  {.pragma: nocov, codegenDecl: "__attribute__((no_sanitize(\"coverage\"))) $# $#$#".}
  {.pragma: nosan, codegenDecl: "__attribute__((disable_sanitizer_instrumentation)) $# $#$#".}

  type
    FuzzTarget = proc (x: typ) {.nimcall, noSideEffect.}
    FuzzMutator = proc (x: var typ; sizeIncreaseHint: Natural, r: var Rand) {.nimcall.}

  var
    buffer: seq[byte] = @[0xf1'u8]
    cached: typ

  proc getInput(x: var typ; data: openArray[byte]): var typ {.nocov, nosan.} =
    if equals(data, buffer):
      result = cached
    else:
      var pos = 1
      fromData(data, pos, x)
      result = x

  proc setInput(x: var typ; data: openArray[byte]; len: int) {.inline.} =
    setLen(buffer, len)
    var pos = 1
    toData(buffer, pos, x)
    assert pos == len
    copyMem(addr data, addr buffer[0], len)
    cached = move x

  proc clearBuffer() {.inline.} =
    setLen(buffer, 1)

  proc testOneInputImpl[T](x: var T; data: openArray[byte]) =
    if data.len > 1: # ignore '\n' passed by LibFuzzer.
      try:
        FuzzTarget(target)(getInput(x, data))
      finally:
        {.emit: "nimTestErrorFlag();".}

  proc customMutatorImpl(x: var typ; data: openArray[byte]; maxLen: int; r: var Rand): int {.nosan.} =
    if data.len > 1:
      x = move getInput(x, data)
    FuzzMutator(mutator)(x, maxLen-x.byteSize, r)
    result = x.byteSize+1 # +1 for the skipped byte
    if result <= maxLen:
      setInput(x, data, result)
    else:
      clearBuffer()
      result = data.len

  proc LLVMFuzzerTestOneInput(data: ptr UncheckedArray[byte], len: int): cint {.exportc.} =
    result = 0
    var x: typ
    testOneInputImpl(x, toOpenArray(data, 0, len-1))

  proc LLVMFuzzerCustomMutator(data: ptr UncheckedArray[byte], len, maxLen: int, seed: int64): int {.
      exportc.} =
    var r = initRand(seed)
    var x: typ
    customMutatorImpl(x, toOpenArray(data, 0, len-1), maxLen, r)

proc commonImpl(target, mutator: NimNode): NimNode =
  let typ = getTypeImpl(target).params[^1][1]
  result = newStmtList(getAst(mutatorImpl(target, mutator, typ)))

macro defaultMutator*(target: proc) =
  commonImpl(target, bindSym"myMutator")

macro customMutator*(target, mutator: proc) =
  commonImpl(target, mutator)
