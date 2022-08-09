# These mutators are crazy. I don't expect anyone using the fuzzer to come up with this.
# Possible alternative mutator: have a distinct NodeIdx with values from 0 to MaxNodes
# That's more inline with LPM and should work just fine.

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
      template toNode: untyped = fromNode.edges[toNodeIdx]
      fromNode.edges.delete(toNodeIdx)
      x.deleteNode(toNode) # bug here!
      result = true

when isMainModule:
  import std/[math, typetraits, algorithm, random]

  const
    MaxRepeat = 10

  type
    GraphMutator = enum
      AddNode,
      DeleteNode,
      MutateNodeData,
      AddEdge,
      DeleteEdge,
      MoveEdge,
      AddFriend,
      MoveNode,

  const
    Weights = cumsummed([
      AddNode: 5,
      DeleteNode: 5,
      MutateNodeData: 25,
      AddEdge: 5,
      DeleteEdge: 5,
      MoveEdge: 10,
      AddFriend: 10,
      MoveNode: 5
    ])

  func sample[E: OrdinalEnum; U](r: var Rand; t: typedesc[E]; cdf: openArray[U]): E =
    assert(cdf.len == t.enumLen)
    assert(float(cdf[^1]) > 0)
    let u = r.rand(float(cdf[^1]))
    E(cdf.upperBound(U(u)) + low(E).ord)

  func mutate[T](input: var Graph[T], mutator: GraphMutator, spareCplx: float, r: var Rand
      ): bool =
    result = false
    case mutator
    of AddNode:
      let data = newInput[T](spareCplx, r)
      input.addNode(data)
      result = true
    of DeleteNode:
      let len = input.nodes.len
      if len > 0:
        let pick = r.rand(0..<len)
        let _ = input.deleteNode(pick)
        result = true
    of MutateNodeData:
      let len = input.nodes.len
      if len > 0:
        let pick = r.rand(0..<len)
        template node: untyped = input.nodes[pick]
        result = mutate(node.data, spareCplx, r)
    of AddEdge:
      let len = input.nodes.len
      if len > 0:
        let pick1 = r.rand(0..<len)
        let pick2 = r.rand(0..<len)
        let _ = input.addEdge(pick1, pick2)
        result = true
    of DeleteEdge:
      let len = input.nodes.len
      if len > 0:
        let pick1 = r.rand(0..<len)
        template node: untyped = input.nodes[pick]
        let len = node.edges.len
        if len > 0:
          let pick2Idx = r.rand(0..<len)
          let _ = input.deleteEdge(pick1, node.edges[pick2Idx])
          result = true
    of MoveEdge:
      let nodesLen = input.nodes.len
      if nodesLen > 0:
        let pick = r.rand(0..<nodesLen)
        template node: untyped = input.nodes[pick]
        let edgesLen = node.edges.len
        if edgesLen > 0:
          let pick1 = r.rand(0..<edgesLen)
          let pick2 = r.rand(0..<nodesLen)
          node.edges[pick1] = pick2
          result = true
    of AddFriend:
      let len = input.nodes.len
      if len > 0:
        let pick = r.rand(0..<len)
        let data = newInput[T](spareCplx, r)
        input.addNode(data)
        input.addEdge(pick, input.nodes.high)
        result = true
    of MoveNode:
      let len = input.nodes.len
      if len > 1:
        let pick1 = r.rand(0..<len)
        let pick2 = r.rand(0..<len)
        input.nodes.swap(pick1, pick2)
        result = true

  func mutate(input: var Graph[T], spareCplx: float, r: var Rand): bool =
    result = false
    for _ in 1..MaxRepeat:
      if input.mutate(r.sample(GraphMutator, Weights), input, spareCplx, r):
        return true

  func complexity[T](input: Graph[T]): float =
    # The space complexity is O(n + m).
    result = 0
    for n in input.nodes.items:
      result += 1 + float(n.edges.len)

  func newInput[T](maxCplx: float, r: var Rand): Graph[T] =
    result = Graph[T]()
    let targetCplx = r.rand(maxCplx)
    var currentCplx = complexity(result)
    while currentCplx < targetCplx:
      let mutator = if r.rand(bool): AddNode else: AddEdge
      result.mutate(mutator, targetCplx - currentCplx, r)
      currentCplx = complexity(result)
    while currentCplx > targetCplx:
      let mutator = if r.rand(bool): RemoveNode else: RemoveEdge
      result.mutate(mutator, targetCplx - currentCplx, r)
      currentCplx = complexity(result)

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

    # Needs the mutator to produce the following diff:
    #import std/with

    #var x: Graph[int]
    #with x:
      #addNode(data = 63)
      #addNode(data = 3)
      #addNode(data = -56)
      #addNode(data = 100)
      #addNode(data = -100)
      #addNode(data = -78)
      #addNode(data = 46)
      #addNode(data = 120)

      #addEdge(`from` = 0, to = 1)
      #addEdge(`from` = 0, to = 2)
      #addEdge(`from` = 1, to = 3)
      #addEdge(`from` = 1, to = 4)
      #addEdge(`from` = 2, to = 5)
      #addEdge(`from` = 2, to = 6)
      #addEdge(`from` = 3, to = 7)
