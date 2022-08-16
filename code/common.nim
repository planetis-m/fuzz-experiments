# Procedures dealing with serialization from/to libFuzzer's input buffer. Since the custom
# mutator is in control of the process, there should be no errors. And if there are, they
# should be fatal and the code should be fixed. User may also run the fuzzer without any
# sanitizer, which means that errors should always be detected.
import std/[options, tables, sets]
from typetraits import supportsCopyMem, distinctBase

type
  EncodingDefect = object of Defect
  DecodingDefect = object of Defect

proc raiseEncodingDefect() {.noinline, noreturn.} =
  raise newException(EncodingDefect, "Can't write bytes to buffer.")

proc raiseDecodingDefect() {.noinline, noreturn.} =
  raise newException(DecodingDefect, "Can't read bytes from buffer.")

proc equals*(a, b: openArray[byte]): bool =
  if a.len != b.len:
    result = false
  else: result = equalMem(addr a, addr b, a.len)

proc byteSize*(x: bool): int {.inline.} = sizeof(x)
proc byteSize*(x: char): int {.inline.} = sizeof(x)
proc byteSize*[T: SomeNumber](x: T): int {.inline.} = sizeof(x)
proc byteSize*[T: enum](x: T): int {.inline.} = sizeof(x)
proc byteSize*[T](x: set[T]): int {.inline.} = sizeof(x)
proc byteSize*(x: string): int {.inline.} = sizeof(int32) + x.len

proc byteSize*[S, T](x: array[S, T]): int {.inline.} =
  when supportsCopyMem(T):
    result = sizeof(x)
  else:
    result = 0
    for elem in x.items: result.inc byteSize(elem)

proc byteSize*[T](x: seq[T]): int {.inline.} =
  when supportsCopyMem(T):
    result = sizeof(int32) + x.len * sizeof(T)
  else:
    result = sizeof(int32)
    for elem in x.items: result.inc byteSize(elem)

proc byteSize*[T](o: SomeSet[T]): int {.inline.} =
  result = sizeof(int32)
  for elem in o.items: result.inc byteSize(elem)

proc byteSize*[K, V](o: (Table[K, V]|OrderedTable[K, V])): int {.inline.} =
  result = sizeof(int32)
  for k, v in o.pairs:
    result.inc byteSize(k)
    result.inc byteSize(v)

proc byteSize*[T](o: ref T): int {.inline.} =
  result = sizeof(bool)
  if o != nil: result.inc byteSize(o[])

proc byteSize*[T](o: Option[T]): int {.inline.} =
  result = sizeof(bool)
  if isSome(o): result.inc byteSize(get(o))

proc byteSize*[T: tuple](o: T): int {.inline.} =
  when supportsCopyMem(T):
    result = sizeof(o)
  else:
    result = 0
    for v in o.fields: result.inc byteSize(v)

proc byteSize*[T: object](o: T): int {.inline.} =
  when supportsCopyMem(T):
    result = sizeof(o)
  else:
    result = 0
    for v in o.fields: result.inc byteSize(v)

proc byteSize*[T: distinct](x: T): int {.inline.} = byteSize(x.distinctBase)

proc writeData*(data: var openArray[byte], pos: var int, buffer: pointer, bufLen: int) =
  if bufLen <= 0:
    return
  if pos + bufLen > data.len:
    raiseEncodingDefect()
  else:
    copyMem(data[pos].addr, buffer, bufLen)
    inc(pos, bufLen)

proc write*[T](data: var openArray[byte], pos: var int, input: T) =
  writeData(data, pos, input.unsafeAddr, sizeof(input))

proc readData*(data: openArray[byte], pos: var int, buffer: pointer, bufLen: int): int =
  result = min(bufLen, data.len - pos)
  if result > 0:
    copyMem(buffer, data[pos].addr, result)
    inc(pos, result)
  else:
    result = 0

proc read*[T](data: openArray[byte], pos: var int, output: var T) =
  if readData(data, pos, output.addr, sizeof(output)) != sizeof(output):
    raiseDecodingDefect()

proc readChar*(data: openArray[byte], pos: var int): char {.inline.} =
  read(data, pos, result)

proc readBool*(data: openArray[byte], pos: var int): bool {.inline.} =
  read(data, pos, result)

proc readInt8*(data: openArray[byte], pos: var int): int8 {.inline.} =
  read(data, pos, result)

proc readInt16*(data: openArray[byte], pos: var int): int16 {.inline.} =
  read(data, pos, result)

proc readInt32*(data: openArray[byte], pos: var int): int32 {.inline.} =
  read(data, pos, result)

proc readInt64*(data: openArray[byte], pos: var int): int64 {.inline.} =
  read(data, pos, result)

proc readUint8*(data: openArray[byte], pos: var int): uint8 {.inline.} =
  read(data, pos, result)

proc readUint16*(data: openArray[byte], pos: var int): uint16 {.inline.} =
  read(data, pos, result)

proc readUint32*(data: openArray[byte], pos: var int): uint32 {.inline.} =
  read(data, pos, result)

proc readUint64*(data: openArray[byte], pos: var int): uint64 {.inline.} =
  read(data, pos, result)

proc readFloat32*(data: openArray[byte], pos: var int): float32 {.inline.} =
  read(data, pos, result)

proc readFloat64*(data: openArray[byte], pos: var int): float64 {.inline.} =
  read(data, pos, result)

proc toData*(data: var openArray[byte]; pos: var int; input: bool) =
  write(data, pos, input)

proc fromData*(data: openArray[byte]; pos: var int; output: var bool) =
  read(data, pos, output)

proc toData*(data: var openArray[byte]; pos: var int; input: char) =
  write(data, pos, input)

proc fromData*(data: openArray[byte]; pos: var int; output: var char) =
  read(data, pos, output)

proc toData*[T: SomeNumber](data: var openArray[byte]; pos: var int; input: T) =
  write(data, pos, input)

proc fromData*[T: SomeNumber](data: openArray[byte]; pos: var int; output: var T) =
  read(data, pos, output)

proc toData*[T: enum](data: var openArray[byte]; pos: var int; input: T) =
  write(data, pos, input)

proc fromData*[T: enum](data: openArray[byte]; pos: var int; output: var T) =
  read(data, pos, output)

proc toData*[T](data: var openArray[byte]; pos: var int; input: set[T]) =
  write(data, pos, input)

proc fromData*[T](data: openArray[byte]; pos: var int; output: var set[T]) =
  read(data, pos, output)

proc toData*(data: var openArray[byte]; pos: var int; input: string) =
  write(data, pos, int32(input.len))
  writeData(data, pos, cstring(input), input.len)

proc fromData*(data: openArray[byte]; pos: var int; output: var string) =
  let len = readInt32(data, pos).int
  output.setLen(len)
  if readData(data, pos, cstring(output), len) != len:
    raiseDecodingDefect()

proc toData*[S, T](data: var openArray[byte]; pos: var int; input: array[S, T]) =
  when supportsCopyMem(T):
    writeData(data, pos, input.unsafeAddr, sizeof(input))
  else:
    for elem in input.items:
      toData(data, pos, elem)

proc fromData*[S, T](data: openArray[byte]; pos: var int; output: var array[S, T]) =
  when supportsCopyMem(T):
    if readData(data, pos, output.addr, sizeof(output)) != sizeof(output):
      raiseDecodingDefect()
  else:
    for i in low(output)..high(output):
      fromData(data, pos, output[i])

proc toData*[T](data: var openArray[byte]; pos: var int; input: seq[T]) =
  write(data, pos, int32(input.len))
  when supportsCopyMem(T):
    if input.len > 0:
      writeData(data, pos, input[0].unsafeAddr, input.len * sizeof(T))
  else:
    for elem in input.items:
      toData(data, pos, elem)

proc fromData*[T](data: openArray[byte]; pos: var int; output: var seq[T]) =
  let len = readInt32(data, pos).int
  output.setLen(len)
  when supportsCopyMem(T):
    if len > 0:
      let bLen = len * sizeof(T)
      if readData(data, pos, output[0].addr, bLen) != bLen:
        raiseDecodingDefect()
  else:
    for i in 0..<len:
      fromData(data, pos, output[i])

proc toData*[T](data: var openArray[byte]; pos: var int; input: SomeSet[T]) =
  write(data, pos, int32(input.len))
  for elem in input.items:
    toData(data, pos, elem)

proc fromData*[T](data: openArray[byte]; pos: var int; output: var SomeSet[T]) =
  let len = readInt32(data, pos).int
  for i in 0..<len:
    var tmp: T
    fromData(data, pos, tmp)
    output.incl(tmp)

proc toData*[K, V](data: var openArray[byte]; pos: var int; input: (Table[K, V]|OrderedTable[K, V])) =
  write(data, pos, int32(input.len))
  for k, v in input.pairs:
    toData(data, pos, k)
    toData(data, pos, v)

proc fromData*[K, V](data: openArray[byte]; pos: var int; output: var (Table[K, V]|OrderedTable[K, V])) =
  let len = readInt32(data, pos).int
  for i in 0 ..< len:
    var key: K
    fromData(data, pos, key)
    fromData(data, pos, mgetOrPut(output, key, default(V)))

proc toData*[T](data: var openArray[byte]; pos: var int; input: ref T) =
  let isSome = input != nil
  toData(data, pos, isSome)
  if isSome:
    toData(data, pos, input[])

proc fromData*[T](data: openArray[byte]; pos: var int; output: var ref T) =
  let isSome = readBool(data, pos)
  if isSome:
    new(output)
    fromData(data, pos, output[])
  else:
    output = nil

proc toData*[T](data: var openArray[byte]; pos: var int; input: Option[T]) =
  let isSome = isSome(input)
  toData(data, pos, isSome)
  if isSome:
    toData(data, pos, get(input))

proc fromData*[T](data: openArray[byte]; pos: var int; output: var Option[T]) =
  let isSome = readBool(data, pos)
  if isSome:
    var tmp: T
    fromData(data, pos, tmp)
    output = some(tmp)
  else:
    output = none[T]()

proc toData*[T: tuple](data: var openArray[byte]; pos: var int; input: T) =
  when supportsCopyMem(T):
    write(data, pos, input)
  else:
    for v in input.fields:
      toData(data, pos, v)

proc toData*[T: object](data: var openArray[byte]; pos: var int; input: T) =
  when supportsCopyMem(T):
    write(data, pos, input)
  else:
    for v in input.fields:
      toData(data, pos, v)

proc fromData*[T: tuple](data: openArray[byte]; pos: var int; output: var T) =
  when supportsCopyMem(T):
    read(data, pos, output)
  else:
    for v in output.fields:
      fromData(data, pos, v)

proc fromData*[T: object](data: openArray[byte]; pos: var int; output: var T) =
  when supportsCopyMem(T):
    read(data, pos, output)
  else:
    for v in output.fields:
      fromData(data, pos, v)

proc toData*[T: distinct](data: var openArray[byte]; pos: var int; input: T) {.inline.} =
  toData(data, pos, input.distinctBase)

proc fromData*[T: distinct](data: openArray[byte]; pos: var int; output: var T) {.inline.} =
  fromData(data, pos, output.distinctBase)
