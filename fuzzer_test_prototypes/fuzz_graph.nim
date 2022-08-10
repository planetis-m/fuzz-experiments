# What about nodes seq, shouldn't it be MaxNodes = nodes.len?
# The Peach format has the ability to specify dynamic dependencies between data.
# https://wiki.mozilla.org/Security/Fuzzing/Peach tag "Relation", attribute "ref"
# Better done as a post-processor step that does culling on nodes? Or on edges.
# A string pragma is also possible but would require regex.
# min limit need significant refactoring let's ignore them, there are none in LibFuzzer anyway.
# TODO: Add a post-processor step.
# Since mutate doesn't always return a new mutation, would it make more sense to remove repeatMutate
# and try to mutate everything at once?

when defined(fuzzer):
  const
    MaxNodes = 8 # User defined, statically limits number of nodes.
  type
    NodeIdx = distinct int
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

when defined(fuzzer) and isMainModule:
  import std/random, ".."/code/buffers
  from typetraits import supportsCopyMem

  proc initialize(): cint {.exportc: "LLVMFuzzerInitialize".} =
    {.emit: "N_CDECL(void, NimMain)(void); NimMain();".}

  proc mutate(data: ptr UncheckedArray[byte], len, maxLen: int): int {.
      importc: "LLVMFuzzerMutate".}

  template `+!`(p: pointer, s: int): untyped =
    cast[pointer](cast[ByteAddress](p) +% s)

  const
    RandomToDefaultRatio = 100

  proc mutateValue[T](value: T; r: var Rand): T =
    result = value
    let size = mutate(cast[ptr UncheckedArray[byte]](addr result), sizeof(T), sizeof(T))
    zeroMem(result.addr +! size, sizeof(T) - size)

  proc mutateEnum(index, itemCount: int; r: var Rand): int =
    if itemCount <= 1: 0
    else: (index + 1 + r.rand(itemCount - 1)) mod itemCount

  proc mutateSeq[T](value: sink seq[T]; userMax: Natural; sizeIncreaseHint: int;
      r: var Rand): seq[T] =
    result = value
    while result.len > 0 and r.rand(bool):
      result.delete(rand(r, result.high))
    while result.len < userMax and sizeIncreaseHint > 0 and
        result.byteSize < sizeIncreaseHint and r.rand(bool):
      let index = rand(r, result.len)
      result.insert(mutate(default(T), sizeIncreaseHint, r), index)
    if result != value:
      return result
    if result.len == 0:
      result.add(mutate(default(T), sizeIncreaseHint, r))
      return result
    else:
      let index = rand(r, result.high)
      result[index] = mutate(result[index], sizeIncreaseHint, r)

  template repeatMutate(call: untyped) =
    if rand(r, RandomToDefaultRatio - 1) == 0:
      return
    var tmp = value
    for i in 1..10:
      value = call
      if value != tmp: return

  proc mutate[T: SomeNumber](value: var T; sizeIncreaseHint: Natural; r: var Rand) =
    repeatMutate(mutateValue(value, r))

  proc mutate[T](value: var seq[T]; sizeIncreaseHint: Natural; r: var Rand) =
    repeatMutate(mutateSeq(value, high(Natural), sizeIncreaseHint, r))

  # User defined mutators
  proc mutate(value: var NodeIdx; sizeIncreaseHint: Natural; r: var Rand) =
    repeatMutate(mutateEnum(value.int, MaxNodes, r).NodeIdx)

  proc mutate[T](value: var seq[Node[T]]; sizeIncreaseHint: Natural; r: var Rand) =
    repeatMutate(mutateSeq(value, MaxNodes, sizeIncreaseHint, r))

  template toPayload*(data; len): untyped =
    toOpenArray(data, 0, len-1)

  template fuzzTarget(x: untyped, typ: typedesc, body: untyped) =
    proc testOneInput(data: ptr UncheckedArray[byte], len: int): cint {.
        exportc: "LLVMFuzzerTestOneInput", raises: [].} =
      result = 0
      var x: typ
      var c: CoderState
      fromData(x, toPayload(data, len), c)
      if c.err: reset(x)
      when defined(dumpFuzzInput): echo x
      body

  fuzzTarget(x, Graph[int]):
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
        x.nodes[0].edges[0] == NodeIdx(1) and
        x.nodes[0].edges[1] == NodeIdx(2) and
        x.nodes[1].edges.len == 2 and
        x.nodes[1].edges[0] == NodeIdx(3) and
        x.nodes[1].edges[1] == NodeIdx(4) and
        x.nodes[2].edges.len == 2 and
        x.nodes[2].edges[0] == NodeIdx(5) and
        x.nodes[2].edges[1] == NodeIdx(6) and
        x.nodes[3].edges.len == 1 and
        x.nodes[3].edges[0] == NodeIdx(7) and
        x.nodes[4].edges.len == 0 and
        x.nodes[5].edges.len == 0 and
        x.nodes[6].edges.len == 0 and
        x.nodes[7].edges.len == 0:
      assert false
