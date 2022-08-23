import std/[random, macros], common, sampler, utf8fix
from typetraits import distinctBase, supportsCopyMem

when not defined(fuzzerStandalone):
  proc initialize(): cint {.exportc: "LLVMFuzzerInitialize".} =
    {.emit: "N_CDECL(void, NimMain)(void); NimMain();".}

  proc mutate*(data: ptr UncheckedArray[byte], len, maxLen: int): int {.
      importc: "LLVMFuzzerMutate".}

template `+!`(p: pointer, s: int): untyped =
  cast[pointer](cast[ByteAddress](p) +% s)

const
  RandomToDefaultRatio* = 100
  DefaultMutateWeight* = 1_000_000
  MaxInitializeDepth* = 200

type
  ByteSized = int8|uint8|byte|bool|char

proc runMutator*[T: SomeNumber](x: var T; sizeIncreaseHint: int; enforceChanges: bool; r: var Rand)
proc runMutator*[T](x: var seq[T]; sizeIncreaseHint: int; enforceChanges: bool; r: var Rand)
proc runMutator*(x: var bool; sizeIncreaseHint: int; enforceChanges: bool; r: var Rand)
proc runMutator*(x: var char; sizeIncreaseHint: int; enforceChanges: bool; r: var Rand)
proc runMutator*(x: var string; sizeIncreaseHint: int; enforceChanges: bool; r: var Rand)
proc runMutator*[T: tuple|object](x: var T; sizeIncreaseHint: int; enforceChanges: bool; r: var Rand)
proc runMutator*[T](x: var ref T; sizeIncreaseHint: int; enforceChanges: bool; r: var Rand)
proc runMutator*[S, T](x: var array[S, T]; sizeIncreaseHint: int; enforceChanges: bool; r: var Rand)

proc flipBit*(bytes: ptr UncheckedArray[byte]; len: int; r: var Rand) =
  ## Flips random bit in the buffer.
  let bit = rand(r, len * 8 - 1)
  bytes[bit div 8] = bytes[bit div 8] xor (1'u8 shl (bit mod 8))

proc flipBit*[T](value: T; r: var Rand): T =
  ## Flips random bit in the value.
  result = value
  flipBit(cast[ptr UncheckedArray[byte]](addr result), sizeof(T), r)

when not defined(fuzzerStandalone):
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

proc newInput*[T](sizeIncreaseHint: int; r: var Rand): T =
  ## Creates new input with a chance of returning default(T).
  runMutator(result, sizeIncreaseHint, false, r)

proc mutateSeq*[T](value: var seq[T]; previous: seq[T]; userMax, sizeIncreaseHint: int;
    r: var Rand): bool =
  let previousSize = previous.byteSize
  while value.len > 0 and r.rand(bool):
    value.delete(rand(r, value.high))
  var currentSize = value.byteSize
  template remainingSize: untyped = sizeIncreaseHint-currentSize+previousSize
  while value.len < userMax and remainingSize > 0 and r.rand(bool):
    let index = rand(r, value.len)
    value.insert(newInput[T](remainingSize, r), index)
    currentSize = value.byteSize
  if value != previous:
    result = true
  elif value.len == 0:
    value.add(newInput[T](remainingSize, r))
    result = true
  else:
    let index = rand(r, value.high)
    runMutator(value[index], remainingSize, true, r)
    result = value != previous

proc mutateByteSizedSeq*[T: ByteSized](value: sink seq[T]; userMax, sizeIncreaseHint: int;
    r: var Rand): seq[T] =
  if r.rand(0..20) == 0:
    result = @[]
  else:
    let oldSize = value.len
    result = value
    result.setLen(max(1, oldSize + sizeIncreaseHint))
    result.setLen(mutate(cast[ptr UncheckedArray[byte]](addr result[0]), oldSize, result.len))
    when T is bool:
      # Fix bool values so UBSan stops complaining.
      for x in 0..<result.len: result[i] = cast[seq[byte]](result)[i] != 0.byte

proc mutateString*(value: sink string; userMax, sizeIncreaseHint: int; r: var Rand): string =
  if r.rand(0..20) == 0:
    result = ""
  else:
    let oldSize = value.len
    result = value
    result.setLen(max(1, oldSize + sizeIncreaseHint))
    result.setLen(mutate(cast[ptr UncheckedArray[byte]](addr result[0]), oldSize, result.len))

proc mutateUtf8String*(value: sink string; userMax, sizeIncreaseHint: int; r: var Rand): string =
  result = mutateString(value, userMax, sizeIncreaseHint, r)
  fixUtf8(result, r)

proc mutateArray*[S, T](value: array[S, T]; r: var Rand): array[S, T] {.inline.} =
  result = mutateValue(value, r)
  when T is bool:
    for i in low(result)..high(result): result[i] = cast[array[S, byte]](result)[i] != 0.byte

template repeatMutate*(call: untyped) =
  if not enforceChanges and rand(r, RandomToDefaultRatio - 1) == 0:
    discard
  else:
    var tmp = value
    for i in 1..10:
      value = call
      if not enforceChanges or value != tmp: return

template repeatMutateInplace*(call: untyped) =
  if not enforceChanges and rand(r, RandomToDefaultRatio - 1) == 0:
    discard
  else:
    var tmp {.inject.} = value
    for i in 1..10:
      let notEqual = call
      if not enforceChanges or notEqual: return

proc mutate*(value: var bool; sizeIncreaseHint: int; enforceChanges: bool; r: var Rand) =
  value = not value

proc mutate*(value: var char; sizeIncreaseHint: int; enforceChanges: bool; r: var Rand) =
  repeatMutate(mutateValue(value, r))

proc mutate*[T: SomeNumber](value: var T; sizeIncreaseHint: int; enforceChanges: bool; r: var Rand) =
  repeatMutate(mutateValue(value, r))

proc mutate*[T: not ByteSized](value: var seq[T]; sizeIncreaseHint: int; enforceChanges: bool; r: var Rand) =
  repeatMutateInplace(mutateSeq(value, tmp, high(int), sizeIncreaseHint, r))

proc mutate*[T: ByteSized](value: var seq[T]; sizeIncreaseHint: int; enforceChanges: bool; r: var Rand) =
  repeatMutate(mutateByteSizedSeq(move value, high(int), sizeIncreaseHint, r))

proc mutate*(value: var string; sizeIncreaseHint: int; enforceChanges: bool; r: var Rand) =
  when defined(fuzzerUtf8Strings):
    repeatMutate(mutateUtf8String(move value, high(int), sizeIncreaseHint, r))
  else:
    repeatMutate(mutateString(move value, high(int), sizeIncreaseHint, r))

proc mutate*[S; T: SomeNumber|bool|char](value: var array[S, T]; sizeIncreaseHint: int;
    enforceChanges: bool; r: var Rand) =
  repeatMutate(mutateArray(value, r))

template sampleAttempt(call: untyped) =
  inc res
  call

proc sample[T: distinct](x: T; s: var Sampler; r: var Rand; res: var int) =
  when compiles(mutate(x, 0, false, r)):
    sampleAttempt(attempt(x, r, DefaultMutateWeight, res))
  else:
    sample(x.distinctBase, s, r, res)

proc sample(x: bool; s: var Sampler; r: var Rand; res: var int) =
  sampleAttempt(attempt(s, r, DefaultMutateWeight, res))

proc sample(x: char; s: var Sampler; r: var Rand; res: var int) =
  sampleAttempt(attempt(s, r, DefaultMutateWeight, res))

proc sample[T: SomeNumber](x: T; s: var Sampler; r: var Rand; res: var int) =
  sampleAttempt(attempt(s, r, DefaultMutateWeight, res))

proc sample[T](x: seq[T]; s: var Sampler; r: var Rand; res: var int) =
  sampleAttempt(attempt(s, r, DefaultMutateWeight, res))

proc sample(x: string; s: var Sampler; r: var Rand; res: var int) =
  sampleAttempt(attempt(s, r, DefaultMutateWeight, res))

proc sample[T: tuple|object](x: T; s: var Sampler; r: var Rand; res: var int) =
  when compiles(mutate(x, 0, false, r)):
    sampleAttempt(attempt(x, r, DefaultMutateWeight, res))
  else:
    for v in fields(x):
      sample(v, s, r, res)

proc sample[T](x: ref T; s: var Sampler; r: var Rand; res: var int) =
  when compiles(mutate(x, 0, false, r)):
    sampleAttempt(attempt(x, r, DefaultMutateWeight, res))
  else:
    if x != nil: sample(x[], s, r, res)

proc sample[S, T](x: array[S, T]; s: var Sampler; r: var Rand; res: var int) =
  when compiles(mutate(x, 0, false, r)):
    sampleAttempt(attempt(x, r, DefaultMutateWeight, res))
  else:
    for i in low(x)..high(x):
      sample(x[i], s, r, res)

template pickMutate(call: untyped) =
  if res > 0:
    dec res
    if res == 0:
      call

proc pick[T: distinct](x: var T; sizeIncreaseHint: int; enforceChanges: bool;
    r: var Rand; res: var int) =
  when compiles(mutate(x, sizeIncreaseHint, enforceChanges, r)):
    pickMutate(mutate(x, sizeIncreaseHint, enforceChanges, r))
  else:
    pick(x.distinctBase, sizeIncreaseHint, enforceChanges, r, res)

proc pick(x: var bool; sizeIncreaseHint: int; enforceChanges: bool;
    r: var Rand; res: var int) =
  pickMutate(mutate(x, sizeIncreaseHint, enforceChanges, r))

proc pick(x: var char; sizeIncreaseHint: int; enforceChanges: bool;
    r: var Rand; res: var int) =
  pickMutate(mutate(x, sizeIncreaseHint, enforceChanges, r))

proc pick[T: SomeNumber](x: var T; sizeIncreaseHint: int; enforceChanges: bool;
    r: var Rand; res: var int) =
  pickMutate(mutate(x, sizeIncreaseHint, enforceChanges, r))

proc pick[T](x: var seq[T]; sizeIncreaseHint: int; enforceChanges: bool; r: var Rand;
    res: var int) =
  pickMutate(mutate(x, sizeIncreaseHint, enforceChanges, r))

proc pick(x: var string; sizeIncreaseHint: int; enforceChanges: bool; r: var Rand;
    res: var int) =
  pickMutate(mutate(x, sizeIncreaseHint, enforceChanges, r))

proc pick[T: tuple](x: var T; sizeIncreaseHint: int; enforceChanges: bool;
    r: var Rand; res: var int) =
  when compiles(mutate(x, sizeIncreaseHint, enforceChanges, r)):
    pickMutate(mutate(x, sizeIncreaseHint, enforceChanges, r))
  else:
    for v in fields(x):
      pick(v, sizeIncreaseHint, enforceChanges, r, res)

template getFieldValue(tmpSym, fieldSym) =
  pick(tmpSym.fieldSym, sizeIncreaseHint, enforceChanges, r, res)

template getKindValue(tmpSym, kindSym) =
  var kindTmp = tmpSym.kindSym
  pick(kindTmp, sizeIncreaseHint, enforceChanges, r, res)
  {.cast(uncheckedAssign).}:
    tmpSym.kindSym = kindTmp

proc foldObjectBody(tmpSym, typeNode: NimNode): NimNode =
  case typeNode.kind
  of nnkEmpty:
    result = newNimNode(nnkNone)
  of nnkRecList:
    result = newStmtList()
    for it in typeNode:
      let x = foldObjectBody(tmpSym, it)
      if x.kind != nnkNone: result.add x
  of nnkIdentDefs:
    expectLen(typeNode, 3)
    let fieldSym = typeNode[0]
    result = getAst(getFieldValue(tmpSym, fieldSym))
  of nnkRecCase:
    let kindSym = typeNode[0][0]
    result = newStmtList(getAst(getKindValue(tmpSym, kindSym)))
    let inner = nnkCaseStmt.newTree(nnkDotExpr.newTree(tmpSym, kindSym))
    for i in 1..<typeNode.len:
      let x = foldObjectBody(tmpSym, typeNode[i])
      if x.kind != nnkNone: inner.add x
    result.add inner
  of nnkOfBranch, nnkElse:
    result = copyNimNode(typeNode)
    for i in 0..typeNode.len-2:
      result.add copyNimTree(typeNode[i])
    let inner = newNimNode(nnkStmtListExpr)
    let x = foldObjectBody(tmpSym, typeNode[^1])
    if x.kind != nnkNone: inner.add x
    result.add inner
  of nnkObjectTy:
    expectKind(typeNode[0], nnkEmpty)
    expectKind(typeNode[1], {nnkEmpty, nnkOfInherit})
    result = newNimNode(nnkNone)
    if typeNode[1].kind == nnkOfInherit:
      let base = typeNode[1][0]
      var impl = getTypeImpl(base)
      while impl.kind in {nnkRefTy, nnkPtrTy}:
        impl = getTypeImpl(impl[0])
      result = foldObjectBody(tmpSym, impl)
    let body = typeNode[2]
    let x = foldObjectBody(tmpSym, body)
    if result.kind != nnkNone:
      if x.kind != nnkNone:
        for i in 0..<result.len: x.add(result[i])
        result = x
    else: result = x
  else:
    error("unhandled kind: " & $typeNode.kind, typeNode)

macro assignObjectImpl(output: typed): untyped =
  let typeSym = getTypeInst(output)
  result = newStmtList()
  let x = foldObjectBody(output, typeSym.getTypeImpl)
  if x.kind != nnkNone: result.add x

proc pick[T: object](x: var T; sizeIncreaseHint: int; enforceChanges: bool;
    r: var Rand; res: var int) =
  when compiles(mutate(x, sizeIncreaseHint, enforceChanges, r)):
    pickMutate(mutate(x, sizeIncreaseHint, enforceChanges, r))
  else:
    assignObjectImpl(x)

proc pick[T](x: var ref T; sizeIncreaseHint: int; enforceChanges: bool;
    r: var Rand; res: var int) =
  when compiles(mutate(x, sizeIncreaseHint, enforceChanges, r)):
    pickMutate(mutate(x, sizeIncreaseHint, enforceChanges, r))
  else:
    if x != nil: pick(x[], sizeIncreaseHint, enforceChanges, r, res)

proc pick[S, T](x: var array[S, T]; sizeIncreaseHint: int; enforceChanges: bool;
    r: var Rand; res: var int) =
  when compiles(mutate(x, sizeIncreaseHint, enforceChanges, r)):
    pickMutate(mutate(x, sizeIncreaseHint, enforceChanges, r))
  else:
    for i in low(x)..high(x):
      pick(x[i], sizeIncreaseHint, enforceChanges, r, res)

proc runMutator*[T: distinct](x: var T; sizeIncreaseHint: int; enforceChanges: bool; r: var Rand) =
  when compiles(mutate(x, sizeIncreaseHint, enforceChanges, r)):
    mutate(x, sizeIncreaseHint, enforceChanges, r)
  else:
    runMutator(x.distinctBase, sizeIncreaseHint, enforceChanges, r)

proc runMutator*[T: SomeNumber](x: var T; sizeIncreaseHint: int; enforceChanges: bool; r: var Rand) =
  mutate(x, sizeIncreaseHint, enforceChanges, r)

proc runMutator*[T](x: var seq[T]; sizeIncreaseHint: int; enforceChanges: bool; r: var Rand) =
  mutate(x, sizeIncreaseHint, enforceChanges, r)

proc runMutator*(x: var string; sizeIncreaseHint: int; enforceChanges: bool; r: var Rand) =
  mutate(x, sizeIncreaseHint, enforceChanges, r)

proc runMutator*(x: var bool; sizeIncreaseHint: int; enforceChanges: bool; r: var Rand) =
  mutate(x, sizeIncreaseHint, enforceChanges, r)

proc runMutator*(x: var char; sizeIncreaseHint: int; enforceChanges: bool; r: var Rand) =
  mutate(x, sizeIncreaseHint, enforceChanges, r)

proc runMutator*[T: tuple|object](x: var T; sizeIncreaseHint: int; enforceChanges: bool; r: var Rand) =
  when compiles(mutate(x, sizeIncreaseHint, enforceChanges, r)):
    mutate(x, sizeIncreaseHint, enforceChanges, r)
  else:
    if not enforceChanges and rand(r, RandomToDefaultRatio - 1) == 0:
      discard
    else:
      var res = 0
      var s: Sampler[int]
      sample(x, s, r, res)
      res = s.selected
      pick(x, sizeIncreaseHint, enforceChanges, r, res)

proc runMutator*[T](x: var ref T; sizeIncreaseHint: int; enforceChanges: bool; r: var Rand) =
  when compiles(mutate(x, sizeIncreaseHint, enforceChanges, r)):
    mutate(x, sizeIncreaseHint, enforceChanges, r)
  else:
    if not enforceChanges and rand(r, RandomToDefaultRatio - 1) == 0:
      discard
    else:
      if x == nil: new(x)
      runMutator(x[], sizeIncreaseHint, enforceChanges, r)

proc runMutator*[S, T](x: var array[S, T]; sizeIncreaseHint: int; enforceChanges: bool; r: var Rand) =
  when compiles(mutate(x, sizeIncreaseHint, enforceChanges, r)):
    mutate(x, sizeIncreaseHint, enforceChanges, r)
  else:
    if not enforceChanges and rand(r, RandomToDefaultRatio - 1) == 0:
      discard
    else:
      var res = 0
      var s: Sampler[int]
      sample(x, s, r, res)
      res = s.selected
      pick(x, sizeIncreaseHint, enforceChanges, r, res)

proc runPostProcessor*[T: distinct](x: var T, depth: int; r: var Rand) =
  when compiles(postProcess(x, r)):
    if depth < 0:
      when not supportsCopyMem(T): reset(x)
    else:
      postProcess(x, r)
  elif compiles(mutate(x, 0, false, r)):
    when compiles(for v in mitems(x): discard):
      if depth < 0:
        when not supportsCopyMem(T): reset(x)
      else:
        for v in mitems(x):
          runPostProcessor(v, depth-1, r)
    elif compiles(for k, v in mpairs(x): discard):
      if depth < 0:
        when not supportsCopyMem(T): reset(x)
      else:
        for k, v in mpairs(x):
          runPostProcessor(v, depth-1, r)
  else:
    runPostProcessor(x.distinctBase, depth-1, r)

proc runPostProcessor*(x: var bool, depth: int; r: var Rand) =
  when compiles(postProcess(x, r)):
    if depth >= 0:
      postProcess(x, r)

proc runPostProcessor*(x: var char, depth: int; r: var Rand) =
  when compiles(postProcess(x, r)):
    if depth >= 0:
      postProcess(x, r)

proc runPostProcessor*[T: SomeNumber](x: var T, depth: int; r: var Rand) =
  when compiles(postProcess(x, r)):
    if depth >= 0:
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

proc runPostProcessor*(x: var string, depth: int; r: var Rand) =
  if depth < 0:
    reset(x)
  else:
    when compiles(postProcess(x, r)):
      postProcess(x, r)
    else:
      for i in 0..<x.len:
        runPostProcessor(x[i], depth-1, r)

proc runPostProcessor*[T: tuple|object](x: var T, depth: int; r: var Rand) =
  if depth < 0:
    when not supportsCopyMem(T): reset(x)
  else:
    when compiles(postProcess(x, r)):
      postProcess(x, r)
    # When there is a user-provided mutator, don't touch private fields.
    elif compiles(mutate(x, 0, false, r)):
      # Guess how to traverse a data structure, if it's even one.
      when compiles(for v in mitems(x): discard):
        for v in mitems(x):
          runPostProcessor(v, depth-1, r)
      elif compiles(for k, v in mpairs(x): discard):
        for k, v in mpairs(x):
          runPostProcessor(v, depth-1, r)
    else:
      for v in fields(x):
        {.cast(uncheckedAssign).}: # todo replace with macro.
          runPostProcessor(v, depth-1, r)

proc runPostProcessor*[T](x: var ref T, depth: int; r: var Rand) =
  if depth < 0:
    reset(x)
  else:
    when compiles(postProcess(x, r)):
      postProcess(x, r)
    else:
      if x != nil: runPostProcessor(x[], depth-1, r)

proc runPostProcessor*[S, T](x: var array[S, T], depth: int; r: var Rand) =
  if depth < 0:
    reset(x)
  else:
    when compiles(postProcess(x, r)):
      postProcess(x, r)
    else:
      for i in low(x)..high(x):
        runPostProcessor(x[i], depth-1, r)

proc myMutator[T](x: var T; sizeIncreaseHint: Natural; r: var Rand) {.nimcall.} =
  runMutator(x, sizeIncreaseHint, true, r)
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
    if data.len > 1: # Ignore '\n' passed by LibFuzzer.
      try:
        FuzzTarget(target)(getInput(x, data))
      finally:
        # Call Nim's compiler api to report unhandled exceptions.
        {.emit: "nimTestErrorFlag();".}

  proc customMutatorImpl(x: var typ; data: openArray[byte]; maxLen: int;
      r: var Rand): int {.nosan.} =
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

  proc LLVMFuzzerCustomMutator(data: ptr UncheckedArray[byte], len, maxLen: int,
      seed: int64): int {.
      exportc.} =
    var r = initRand(seed)
    var x: typ
    customMutatorImpl(x, toOpenArray(data, 0, len-1), maxLen, r)

proc commonImpl(target, mutator: NimNode): NimNode =
  let typ = getTypeImpl(target).params[^1][1]
  result = getAst(mutatorImpl(target, mutator, typ))

macro defaultMutator*(target: proc) =
  commonImpl(target, bindSym"myMutator")

macro customMutator*(target, mutator: proc) =
  commonImpl(target, mutator)
