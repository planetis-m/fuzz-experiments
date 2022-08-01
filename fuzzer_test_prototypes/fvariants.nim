import std/random

proc quitOrDebug() {.noreturn, importc: "abort", header: "<stdlib.h>", nodecl.}

type
  Fruit = enum
    Apple, Banana, Orange

  Bar = object
    b: bool
    case kind: Fruit
    of Banana, Orange:
      bad: float
      banana: int
    of Apple: apple: int
    a: float

proc randBool(r: var Rand; n = 2): bool {.inline.} =
  # Return true with probability about 1-of-n.
  r.rand(n-1) == 0

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

proc readBool*(x: var Unstructured): bool =
  read(x, result)

proc readInt64*(x: var Unstructured): int64 =
  read(x, result)

proc readFloat64*(x: var Unstructured): float64 =
  read(x, result)

proc write[T](x: var Unstructured, v: T) =
  writeData(x, addr v, sizeof(v))

proc write(x: var Unstructured; o: Bar) =
  for v in o.fields:
    write(x, v)

proc initFromBin(dest: var Bar; x: var Unstructured) {.nodestroy.} =
  read(x, dest.b)
  {.cast(uncheckedAssign).}:
    read(x, dest.kind)
  case dest.kind
  of Banana, Orange:
    read(x, dest.bad)
    read(x, dest.banana)
  of Apple:
    read(x, dest.apple)
  read(x, dest.a)

proc byteSize(o: Bar): int =
  result = 0
  for v in o.fields: inc result, sizeof(v)

proc mutate*(data: ptr UncheckedArray[byte], len, maxLen: int): int {.
    importc: "LLVMFuzzerMutate".}

template `+!`(p: pointer, s: int): untyped =
  cast[pointer](cast[ByteAddress](p) +% s)

proc mutate[T: enum and Ordinal](v: T; sizeIncreaseHint: int, r: var Rand): T =
  const count = high(T).ord - low(T).ord + 1
  if count <= 1: low(T)
  else: T((v.ord + 1 + rand(r, count - 1)) mod count)

proc mutateVal[T](v: T): T =
  result = v
  let size = mutate(cast[ptr UncheckedArray[byte]](addr result), sizeof(T), sizeof(T))
  zeroMem(result.addr +! size, sizeof(T) - size)

proc mutate(v: int; a: int, b: var Rand): int {.inline.} =
  mutateVal(v)

proc mutate(v: float; a: int, b: var Rand): float {.inline.} =
  mutateVal(v)

proc mutate(v: bool; a: int, b: var Rand): bool {.inline.} =
  not v

type
  Mutation = enum
    None,
    Switch,
    Mutate,
    Copy

proc mutateImpl(dest: var Bar, source: Bar; sizeIncreaseHint: int, r: var Rand) =
  case r.rand(None..Copy)
  of None: discard
  of Switch:
    var kind: Fruit
    kind = mutate(kind, sizeIncreaseHint, r)
    {.cast(uncheckedAssign).}:
      dest.kind = kind
  of Mutate: # This switches branch too?
    for field in fields(dest):
      field = mutate(field, sizeIncreaseHint, r)
  of Copy:
    if randBool(r, 10): dest.b = source.b
    if dest.kind == source.kind:
      case dest.kind
      of Orange, Banana:
        if randBool(r, 10): dest.bad = source.bad
        if randBool(r, 10): dest.banana = source.banana
      of Apple:
        if randBool(r, 10): dest.apple = source.apple
    if randBool(r, 10): dest.a = source.a

proc customMutator*(data: ptr UncheckedArray[byte], len, maxLen: int, seed: int64): int {.
    exportc: "LLVMFuzzerCustomMutator".} =
  var dest: Bar
  if len >= dest.byteSize: # remove this
    var u = toUnstructured(data, len)
    initFromBin(dest, u)
  let source = dest
  var gen = initRand(seed)
  mutateImpl(dest, source, maxLen - dest.byteSize, gen)
  result = dest.byteSize
  if result <= maxLen:
    var writeStr = toUnstructured(data, maxLen)
    writeStr.write(dest)
  else:
    result = len

proc customCrossOver(data1: ptr UncheckedArray[byte], len1: int,
    data2: ptr UncheckedArray[byte], len2: int, res: ptr UncheckedArray[byte],
    maxResLen: int, seed: int64): int {.
    exportc: "LLVMFuzzerCustomCrossOver".} =
  var source: Bar
  if len1 >= source.byteSize:
    var u = toUnstructured(data1, len1)
    initFromBin(source, u)
  var dest: Bar
  if len2 >= dest.byteSize:
    var u = toUnstructured(data2, len2)
    initFromBin(dest, u)
  var gen = initRand(seed)
  mutateImpl(dest, source, maxResLen - dest.byteSize, gen)
  result = dest.byteSize
  if result <= maxResLen:
    var writeStr = toUnstructured(res, maxResLen)
    writeStr.write(dest)
  else:
    result = 0

proc fuzzMe(s: Bar) =
  if s.kind in {Banana, Orange} and s.banana == 0xdeadbeef and s.bad > 100:
    echo "PANIC!"; quitOrDebug()

proc initialize(): cint {.exportc: "LLVMFuzzerInitialize".} =
  {.emit: "N_CDECL(void, NimMain)(void); NimMain();".}

proc testOneInput(data: ptr UncheckedArray[byte], len: int): cint {.
    exportc: "LLVMFuzzerTestOneInput", raises: [].} =
  result = 0
  var x: Bar
  if len < x.byteSize: return
  var u = toUnstructured(data, len)
  initFromBin(x, u)
  fuzzMe(x)
