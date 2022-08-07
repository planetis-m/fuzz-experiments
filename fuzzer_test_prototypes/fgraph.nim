type
  Graph*[T] = object
    nodes: seq[Node[T]]

  Node[T] = object
    data: T
    edges: seq[int]

proc `[]`*[T](x: Graph[T]; idx: Natural): lent T {.inline.} = x.nodes[idx].data
proc `[]`*[T](x: var Graph[T]; idx: Natural): var T {.inline.} = x.nodes[idx].data

proc addNode*[T](x: var Graph[T]; data: sink T) {.nodestroy.} =
  x.nodes.add Node[T](data: data, edges: @[])

proc deleteNode*[T](x: var Graph[T]; idx: Natural): bool =
  result = false
  if idx < x.nodes.len:
    x.nodes.delete(idx)
    for n in x.nodes.mitems:
      if (let position = n.edges.find(idx); position != -1):
        n.edges.delete(position)
    result = true

proc addEdge*[T](x: var Graph[T]; `from`, to: Natural): bool =
  result = false
  if `from` < x.nodes.len and to < x.nodes.len:
    x.nodes[`from`].edges.add(to)
    result = true

proc deleteEdge*[T](x: var Graph[T]; `from`, to: Natural): bool =
  result = false
  if `from` < x.nodes.len and to < x.nodes.len:
    template fromNode: Node = x.nodes[`from`]
    if (let toNodeIdx = fromNode.edges.find(to); toNodeIdx != -1):
      template toNode: Node = x.nodes[toNodeIdx]
      fromNode.edges.delete(toNodeIdx)
      x.deleteNode(toNode)
      result = true

when isMainModule:
  import std/[math, typetraits, algorithm, random]

  type
    GraphMutator = enum
      AddNode,
      RemoveNode,
      MutateNodeData,
      AddEdge,
      RemoveEdge,
      MoveEdge,
      AddFriend,
      MoveNode,

  const
    Weights = cumsummed([
      AddNode: 5,
      RemoveNode: 5,
      MutateNodeData: 25,
      AddEdge: 5,
      RemoveEdge: 5,
      MoveEdge: 10,
      AddFriend: 10,
      MoveNode: 5
    ])

  proc sample[E: OrdinalEnum; U](r: var Rand; t: typedesc[E]; cdf: openArray[U]): E =
    assert(cdf.len == t.enumLen)
    assert(float(cdf[^1]) > 0)
    let u = r.rand(float(cdf[^1]))
    E(cdf.upperBound(U(u)) + low(E).ord)

  fuzzTarget(graph, Graph[int8]):
    when defined(dumpFuzzInput): echo x
    if graph.nodes.len == 8 and
        graph.nodes[0].data == 63 and
        graph.nodes[1].data == 3 and
        graph.nodes[2].data == -56 and
        graph.nodes[3].data == 100 and
        graph.nodes[4].data == -100 and
        graph.nodes[5].data == -78 and
        graph.nodes[6].data == 46 and
        graph.nodes[7].data == 120 and

        graph.nodes[0].edges.len == 2 and
        graph.nodes[0].edges[0] == 1 and
        graph.nodes[0].edges[1] == 2 and
        graph.nodes[1].edges.len == 2 and
        graph.nodes[1].edges[0] == 3 and
        graph.nodes[1].edges[1] == 4 and
        graph.nodes[2].edges.len == 2 and
        graph.nodes[2].edges[0] == 5 and
        graph.nodes[2].edges[1] == 6 and
        graph.nodes[3].edges.len == 1 and
        graph.nodes[3].edges[0] == 7 and
        graph.nodes[4].edges.len == 0 and
        graph.nodes[5].edges.len == 0 and
        graph.nodes[6].edges.len == 0 and
        graph.nodes[7].edges.len == 0:
      assert false
