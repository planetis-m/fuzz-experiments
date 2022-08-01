import std/random

const
  RandomToDefaultRatio = 100
  MaxInitializeDepth = 200
  DefaultMutateWeight = 1000000

type
  Mutation* = enum
    None,
    Add,    # Adds new field with default value.
    Mutate, # Mutates field contents.
    Delete, # Deletes field.
    Copy,   # Copy values copied from another field.
    Clone   # Create new field with value copied from another.

type
  FieldMutator = object
    sizeIncreaseHint: int
    enforceChanges: bool
    m: Mutator
  Mutator = object
    r: Rand

template `+!`(p: pointer, s: int): untyped =
  cast[pointer](cast[ByteAddress](p) +% s)

proc mutate(data: ptr UncheckedArray[byte], len, maxLen: int): int {.
    importc: "LLVMFuzzerMutate".}

proc mutateValue[T](m: var Mutator, v: T): T =
  result = v
  let size = mutate(cast[ptr UncheckedArray[byte]](addr result), sizeof(T), sizeof(T))
  zeroMem(result.addr +! size, sizeof(T) - size)

proc mutateString(m: var Mutator; value: string; sizeIncreaseHint: int): string =
  # Randomly return empty strings as LLVMFuzzerMutate does not produce them.
  if not bool(m.r.rand(0..20)):
    return ""
  result = value
  let newSize = value.len + sizeIncreaseHint
  result.setLen(max(1, newSize))
  result.setLen(mutate(cast[ptr UncheckedArray[byte]](addr result[0]), value.len, result.len))

template repeatMutate(mutateCall: untyped) =
  if not f.enforceChanges and
      rand(f.m.r, RandomToDefaultRatio - 1) == 0:
    return
  var tmp = value
  for i in 0..<10:
    value = mutateCall
    if not f.enforceChanges or value != tmp:
      return

proc mutate(f: var FieldMutator; value: var uint32) =
  repeatMutate(mutateValue(f.m, value))

proc mutate(f: var FieldMutator; value: var string) =
  repeatMutate(mutateValue(f.m, value, f.sizeIncreaseHint))

proc flipBit(bytes: openarray[byte]; r: var Rand) =
  # Flips random bit in the buffer.
  let bit = rand(r, bytes.len * 8 - 1)
  bytes[bit div 8] = bytes[bit div 8] xor (1 shl (bit mod 8))

proc flipBit[T](value: T; r: var Rand): T =
  # Flips random bit in the value.
  result = value
  flipBit(sizeof(T), cast[ptr UncheckedArray[byte]](addr result), r)

proc randBool(r: var Rand; n = 2): bool {.inline.} =
  # Return true with probability about 1-of-n.
  r.rand(n-1) == 0

proc mutateEnum(index: int; itemCount: int): int =
  if itemCount <= 1: 0
  else: (index + 1 + rand(m.r, itemCount - 1)) mod itemCount
  #assert(T is Ordinal)
  #result = T(rand(m.r, ord(low(T)), ord(high(T))))

proc mutateInt32(value: int32): int32 =
  flipBit(value, m.r)

proc mutateInt64(value: int64): int64 =
  flipBit(value, m.r)

proc mutateUInt32(value: uint32): uint32 =
  flipBit(value, m.r)

proc mutateUInt64*(value: uint64): uint64 =
  flipBit(value, m.r)

proc mutateFloat32(value: float32): float32 =
  flipBit(value, m.r)

proc mutateFloat64(value: float64): float64 =
  flipBit(value, m.r)

proc mutateBool(value: bool): bool =
  not value

proc insert(x: var string, item: char, i = 0.Natural) {.noSideEffect.} =
  let xl = x.len
  setLen(x, xl+1)
  var j = xl-1
  while j >= i:
    x[j+1] = x[j]
    dec(j)
  x[i] = item

proc randChar(r: var Rand): char {.inline.} =
  char(rand(m.r, ord(char.high))

proc mutateString(value: string; sizeIncreaseHint: int): string =
  result = value
  while result.len != 0 and randBool(m.r):
    result.delete(rand(m.r, high(result))
  while sizeIncreaseHint > 0 and result.len < sizeIncreaseHint and randBool(m.r):
    let index = rand(m.r, len(result))
    result.insert(randChar(m.r)), index)
  if result != value:
    return result
  if result.len == 0:
    result.add(randChar(m.r))
    return result
  else:
    flipBit(result.len, cast[ptr UncheckedArray[uint8]](addr result[0]), m.r)
