# Compile with: nim c --cc:clang --mm:arc --panics:on -d:useMalloc -t:"-fsanitize=fuzzer,address,undefined" -l:"-fsanitize=fuzzer,address,undefined" -d:nosignalhandler --nomain:on -d:release -g -d:runFuzzTests fuzz_graph_cache
# Runs at 7200 exec/s versus previous one at 5500 exec/s!
# -seed=2998840246 3891635133
when defined(runFuzzTests):
  const
    MaxNodes = 8 # User defined, statically limits number of nodes.
    MaxEdges = 2 # Limits number of edges

  type
    NodeIdx = distinct int

  proc `$`(x: NodeIdx): string {.borrow.}
  proc `==`(a, b: NodeIdx): bool {.borrow.}
else:
  type
    NodeIdx = int

type
  Graph*[T] = object
    nodes: seq[Node[T]]

  Node[T] = object
    data: T
    edges: seq[NodeIdx]

proc `[]`*[T](x: Graph[T]; idx: Natural): lent T {.inline.} = x.nodes[idx].data
proc `[]`*[T](x: var Graph[T]; idx: Natural): var T {.inline.} = x.nodes[idx].data

proc addNode*[T](x: var Graph[T]; data: sink T) {.nodestroy.} =
  x.nodes.add Node[T](data: data, edges: @[])

proc deleteNode*[T](x: var Graph[T]; idx: Natural) =
  if idx < x.nodes.len:
    x.nodes.delete(idx)
    for n in x.nodes.mitems:
      if (let position = n.edges.find(idx.NodeIdx); position != -1):
        n.edges.delete(position)

proc addEdge*[T](x: var Graph[T]; `from`, to: Natural) =
  if `from` < x.nodes.len and to < x.nodes.len:
    x.nodes[`from`].edges.add(to.NodeIdx)

proc deleteEdge*[T](x: var Graph[T]; `from`, to: Natural) =
  if `from` < x.nodes.len and to < x.nodes.len:
    template fromNode: untyped = x.nodes[`from`]
    if (let toNodeIdx = fromNode.edges.find(to.NodeIdx); toNodeIdx != -1):
      template toNode: untyped = fromNode.edges[toNodeIdx]
      fromNode.edges.delete(toNodeIdx)
      #x.deleteNode(toNode.int) #sneaky bug?

when defined(runFuzzTests) and isMainModule:
  import std/[random, sets], ".."/code/[common, sampler]
  from typetraits import distinctBase

  proc initialize(): cint {.exportc: "LLVMFuzzerInitialize".} =
    {.emit: "N_CDECL(void, NimMain)(void); NimMain();".}

  when not defined(fuzzSa):
    proc mutate(data: ptr UncheckedArray[byte], len, maxLen: int): int {.
        importc: "LLVMFuzzerMutate".}

  template `+!`(p: pointer, s: int): untyped =
    cast[pointer](cast[ByteAddress](p) +% s)

  const
    RandomToDefaultRatio = 100
    DefaultMutateWeight = 1000000

  proc mutate[T: SomeNumber](value: var T; sizeIncreaseHint: Natural; r: var Rand)
  proc mutate[T](value: var seq[T]; sizeIncreaseHint: Natural; r: var Rand)
  proc mutate[T: object](value: var T; sizeIncreaseHint: Natural; r: var Rand)

  proc flipBit(bytes: ptr UncheckedArray[byte]; len: int; r: var Rand) =
    # Flips random bit in the buffer.
    let bit = rand(r, len * 8 - 1)
    bytes[bit div 8] = bytes[bit div 8] xor (1'u8 shl (bit mod 8))

  proc flipBit[T](value: T; r: var Rand): T =
    # Flips random bit in the value.
    result = value
    flipBit(cast[ptr UncheckedArray[byte]](addr result), sizeof(T), r)

  when not defined(fuzzSa):
    proc mutateValue[T](value: T; r: var Rand): T =
      result = value
      let size = mutate(cast[ptr UncheckedArray[byte]](addr result), sizeof(T), sizeof(T))
      zeroMem(result.addr +! size, sizeof(T) - size)
  else:
    proc mutateValue[T](value: T; r: var Rand): T =
      flipBit(value, r)

  proc mutateEnum(index, itemCount: int; r: var Rand): int =
    if itemCount <= 1: 0
    else: (index + 1 + r.rand(itemCount - 1)) mod itemCount

  proc mutateSeq[T](value: sink seq[T]; userMax: Natural; sizeIncreaseHint: int;
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

  proc sample[T: distinct](x: T, depth: int, s: var Sampler; r: var Rand; res: var int) =
    sample(x.distinctBase, depth, s, r, res)

  proc sample[T: SomeNumber](x: T, depth: int, s: var Sampler; r: var Rand; res: var int) =
    inc res
    test(s, r, DefaultMutateWeight, res)

  proc sample[T](x: seq[T], depth: int, s: var Sampler; r: var Rand; res: var int) =
    inc res
    test(s, r, DefaultMutateWeight, res)

  proc sample[T: object](x: T, depth: int, s: var Sampler; r: var Rand; res: var int) =
    for v in fields(x):
      sample(v, depth, s, r, res)

  proc pick[T: distinct](x: var T, depth: int, sizeIncreaseHint: int; r: var Rand; res: var int) =
    pick(x.distinctBase, depth, sizeIncreaseHint, r, res)

  template pickMutate(call: untyped) =
    if res > 0:
      dec res
      if res == 0:
        call

  proc pick[T: SomeNumber](x: var T, depth: int, sizeIncreaseHint: int; r: var Rand; res: var int) =
    pickMutate(mutate(x, sizeIncreaseHint, r))

  proc pick[T](x: var seq[T], depth: int, sizeIncreaseHint: int; r: var Rand; res: var int) =
    pickMutate(mutate(x, sizeIncreaseHint, r))

  proc pick[T: object](x: var T, depth: int, sizeIncreaseHint: int; r: var Rand; res: var int) =
    for v in fields(x):
      pick(v, depth, sizeIncreaseHint, r, res)

  proc mutateObj[T: object](value: var T; sizeIncreaseHint: int;
      r: var Rand) =
    var res = 0
    var s: Sampler[int]
    sample(value, 0, s, r, res)
    res = s.selected
    pick(value, 0, sizeIncreaseHint, r, res)

  template repeatMutate(call: untyped) =
    if rand(r, RandomToDefaultRatio - 1) == 0:
      #reset(value)
      return
    var tmp = value
    for i in 1..10:
      value = call
      if value != tmp: return

  proc mutate[T: SomeNumber](value: var T; sizeIncreaseHint: Natural; r: var Rand) =
    repeatMutate(mutateValue(value, r))

  proc mutate[T](value: var seq[T]; sizeIncreaseHint: Natural; r: var Rand) =
    repeatMutate(mutateSeq(value, high(Natural), sizeIncreaseHint, r))

  proc mutate[T: object](value: var T; sizeIncreaseHint: Natural; r: var Rand) =
    if rand(r, RandomToDefaultRatio - 1) == 0:
      #reset(value)
      return
    mutateObj(value, sizeIncreaseHint, r)

  # User defined mutators
  proc mutate(value: var NodeIdx; sizeIncreaseHint: Natural; r: var Rand) =
    repeatMutate(mutateEnum(value.int, MaxNodes, r).NodeIdx)

  proc mutate[T](value: var seq[Node[T]]; sizeIncreaseHint: Natural; r: var Rand) =
    repeatMutate(mutateSeq(value, MaxNodes, sizeIncreaseHint, r))

  proc mutate(value: var seq[NodeIdx]; sizeIncreaseHint: Natural; r: var Rand) =
    repeatMutate(mutateSeq(value, MaxEdges, sizeIncreaseHint, r))

  {.pragma: nosan, codegenDecl: "__attribute__((disable_sanitizer_instrumentation)) $# $#$#".}

  template defaultMutator(typ: typedesc) =
    var
      buffer: seq[byte] = @[0xf1'u8]
      cache: typ

    proc testOneInput(data: ptr UncheckedArray[byte], len: int): cint {.
        exportc: "LLVMFuzzerTestOneInput", raises: [].} =
      result = 0
      if len <= 1: return # ignore '\n' passed by LibFuzzer.
      if equals(toOpenArray(data, 0, len-1), buffer):
        fuzzTarget(cache)
      else:
        var y: typ
        var pos = 1
        fromData(toOpenArray(data, 0, len-1), pos, y)
        fuzzTarget(y)

    proc customMutator(data: ptr UncheckedArray[byte], len, maxLen: int, seed: int64): int {.
        exportc: "LLVMFuzzerCustomMutator", nosan.} =
      var r = initRand(seed)
      var y: typ
      if len > 1:
        var pos = 1
        fromData(toOpenArray(data, 0, len-1), pos, y)
      mutate(y, maxLen-y.byteSize, r)
      result = y.byteSize+1 # +1 for the skipped byte
      if result <= maxLen:
        setLen(buffer, result)
        var pos = 1
        toData(buffer, pos, y)
        assert pos == result
        copyMem(data, addr buffer[0], result)
        cache = move y
      else: result = len

  func fuzzTarget(x: Graph[int8]) =
    when defined(dumpFuzzInput): debugEcho(x)
    if x.nodes.len == 8 and
        x.nodes[0].data == 63 and
        x.nodes[1].data == 3 and
        x.nodes[2].data == -56 and
        x.nodes[3].data == 100 and
        x.nodes[4].data == -100 and
        x.nodes[5].data == -78 and
        x.nodes[6].data == 46 and
        x.nodes[7].data == 120 and

        x.nodes[0].edges.len == 2 and
        x.nodes[0].edges[0] == 1.NodeIdx and
        x.nodes[0].edges[1] == 2.NodeIdx and
        x.nodes[1].edges.len == 2 and
        x.nodes[1].edges[0] == 3.NodeIdx and
        x.nodes[1].edges[1] == 4.NodeIdx and
        x.nodes[2].edges.len == 2 and
        x.nodes[2].edges[0] == 5.NodeIdx and
        x.nodes[2].edges[1] == 6.NodeIdx and
        x.nodes[3].edges.len == 1 and
        x.nodes[3].edges[0] == 7.NodeIdx and
        x.nodes[4].edges.len == 0 and
        x.nodes[5].edges.len == 0 and
        x.nodes[6].edges.len == 0 and
        x.nodes[7].edges.len == 0:
      doAssert false

  defaultMutator(Graph[int8])

  #(nodes: @[
    #(data: 63, edges: @[1, 2]),
    #(data: 3, edges: @[3, 4]),
    #(data: -56, edges: @[5, 6]),
    #(data: 100, edges: @[7]),
    #(data: -100, edges: @[]),
    #(data: -78, edges: @[]),
    #(data: 46, edges: @[]),
    #(data: 120, edges: @[])
  #])
