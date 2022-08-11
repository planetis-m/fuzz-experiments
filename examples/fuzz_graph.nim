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
  import mutator

  proc mutate(value: var NodeIdx; sizeIncreaseHint: Natural; r: var Rand) =
    repeatMutate(mutateEnum(value.int, MaxNodes, r).NodeIdx)

  proc mutate[T](value: var seq[Node[T]]; sizeIncreaseHint: Natural; r: var Rand) =
    repeatMutate(mutateSeq(value, MaxNodes, sizeIncreaseHint, r))

  proc mutate(value: var seq[NodeIdx]; sizeIncreaseHint: Natural; r: var Rand) =
    repeatMutate(mutateSeq(value, MaxEdges, sizeIncreaseHint, r))

  fuzzTarget(x, Graph[int8]):
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
      assert false
