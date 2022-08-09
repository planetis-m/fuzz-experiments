when defined(fuzzer):
  type
    NodeIdx = distinct int
else:
  type
    NodeIdx = int

type
  Graph*[T] = object
    nodes: seq[Node[T]]

  Node[T] = object
    data: T
    edges: seq[NodeIdx]

when defined(fuzzer):
  proc `==`(a, b: NodeIdx): bool {.borrow.}

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
      #x.deleteNode(toNode.int)

when isMainModule:
  import std/random

  const
    MaxNodes = 8
    RandomToDefaultRatio = 100

  proc mutateEnum(index: int; itemCount: int; r: var Rand): int =
    if itemCount <= 1: 0
    else: (index + 1 + r.rand(itemCount - 1)) mod itemCount

  template repeatMutate(call: untyped) =
    if rand(r, RandomToDefaultRatio - 1) == 0:
      return
    var tmp = value
    for i in 1..10:
      value = call
      if value != tmp: return

  proc mutate(value: var NodeIdx; sizeIncreaseHint: Natural; r: var Rand) =
    repeatMutate(mutateEnum(value.int, MaxNodes, r).NodeIdx)

  proc testOneInput(data: ptr UncheckedArray[byte], len: int): cint {.
    exportc: "LLVMFuzzerTestOneInput", raises: [].} =
    result = 0
    when defined(dumpFuzzInput): echo x
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
