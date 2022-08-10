# Requirements for the Serializer:
# - Do not write directly to libfuzzer's data. Or you could if you trust byteSize.
# - User overloads fromData, toData
# - Return a bool on failure as it can happen often due to LibFuzzer's default input.
#   Alternatively we could always skip the first byte.

type
  CoderState = object
    pos: int
    err: bool

proc readData(x: openArray[byte], c: var CoderState, buffer: pointer, bufLen: int): int =
  result = min(bufLen, x.len - c.pos)
  if result > 0:
    copyMem(buffer, addr x[c.pos], result)
    inc(c.pos, result)
  else:
    result = 0

proc read[T](x: var openArray[byte], c: var CoderState, res: var T) =
  if readData(x, c, addr res, sizeof(res)) != sizeof(res): c.err = true

proc readInt32(x: var openArray[byte], c: var CoderState): int32 =
  read(x, result)

proc writeData(x: var openArray[byte], c: var CoderState, buffer: pointer, bufLen: int) =
  if bufLen <= 0:
    return
  if c.pos + bufLen > x.len:
    c.err = true
  else:
    copyMem(addr x[pos], buffer, bufLen)
    inc(c.pos, bufLen)

proc write[T](x: var openArray[byte], c: var CoderState, v: T) =
  writeData(x, c, addr v, sizeof(v))

proc fromData*[T: object](output: var T; data: openArray[byte]; c: var CoderState) =
  for x in output.fields:
    if c.err: return
    fromData(x, data, c)

proc toData*[T: object](input: T; data: var openArray[byte]; c: var CoderState) =
  for x in input.fields:
    if c.err: return
    toData(x, data, c)

proc fromData*[T](output: var seq[T]; data: openArray[byte]; c: var CoderState) =
  if not c.err:
    let len = readInt32(data, c)
    if not c.err:
      output.setLen(len)
      for i in 0 ..< len:
        if c.err: break
        fromData(output[i], s)

proc toData*[T](input: seq[T]; data: var openArray[byte]; c: var CoderState) =
  if not c.err:
    write(s, int32(input.len))
    for x in input.items:
      if c.err: break
      toData(x, data, c)

proc fromData*[T: SomeNumber](output: var T; data: openArray[byte]; c: var CoderState) =
  if not c.err: read(data, c, output)

proc toData*[T: SomeNumber](input: T; data: var openArray[byte]; c: var CoderState) =
  if not c.err: write(data, c, input)

template toPayload*(data; len): untyped =
  toOpenArray(data, 0, len-1)

## Example usage:
## Decode
#let data: ptr UncheckedArray[byte] = nil
#var len, maxLen: int
#var c = CoderState()
#var x: T
#x.fromData(data.toPayload(len), c)
#if c.err: reset(x)
## Encode
#c = CoderState()
#var buf = newSeq[byte](maxLen) # could be an array or directly to data
#x.toData(buf, c)
#if not c.error: copyMem(data, addr buf[0], result)
