import ".."/arbitrary

proc fuzzMe(data: openarray[byte]): bool =
  result = data.len >= 3 and
    data[0].char == 'F' and
    data[1].char == 'U' and
    data[2].char == 'Z' and
    data[3].char == 'Z' # :‑<

proc initialize(): cint {.exportc: "LLVMFuzzerInitialize".} =
  {.emit: "N_CDECL(void, NimMain)(void); NimMain();".}

proc testOneInput(data: ptr UncheckedArray[byte], len: int): cint {.
    exportc: "LLVMFuzzerTestOneInput", raises: [].} =
  result = 0
  var x = toUnstructured(data, len)
  #var data: seq[byte]
  #var keepGoing = readBool(x)
  #while keepGoing:
    #data.add x.readInt[:byte]
    #keepGoing = readBool(x)
  let data = x.readBytes(x.byteSize)
  discard fuzzMe(data)
