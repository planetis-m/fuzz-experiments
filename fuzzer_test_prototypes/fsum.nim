import ".."/arbitrary, std/math

proc sum(x: openArray[float32]): float32 =
  result = 0'f32
  for b in items(x):
    result = if isNaN(b): result else: result + b

proc quitOrDebug() {.noreturn, importc: "abort", header: "<stdlib.h>", nodecl.}

proc testOneInput(data: ptr UncheckedArray[byte], len: int): cint {.
    exportc: "LLVMFuzzerTestOneInput", raises: [].} =
  var x = toUnstructured(data, len)
  let len = x.byteSize div sizeof(float32)
  var copy = newSeq[float32](len)
  for i in 0..<len:
    copy[i] = x.readFloat32()
  let res = sum(copy)
  if isNaN(res):
    quitOrDebug()
