# Requirements for the Serializer:
# - Do not write directly to libfuzzer's data. Or you could.
# - User overloads fromData, toData
# - Return a bool on failure as it can happen often due to LibFuzzer's default input.
#   Alternatively we could always skip the first byte.

type
  State = object
    pos: int
    err: bool

template toPayload*(data; len): untyped =
  toOpenArray(data, 0, len-1)

proc fromData*[T](output: var T; data: openArray[byte]; c: var State) =
proc toData*[](input: T; data: var openArray[byte]; c: var State) =


# Example usage:
let data: ptr UncheckedArray[byte] = nil
var len = 0
var c = State()
var x: T
x.fromData(data.toPayload(len), c)
if c.err: reset(x)

c = State()
var buffer = newSeq[byte](maxLen)
x.toData(buffer, c)
if not c.error: copyMem(data, addr buffer[0], result)
