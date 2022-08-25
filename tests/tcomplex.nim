import mutator

type
  ContentNodeKind = enum
    P, Br, Text
  ContentNode = ref object
    case kind: ContentNodeKind
    of P: pChildren: seq[ContentNode]
    of Br: discard
    of Text: textStr: string

func `==`(a, b: ContentNode): bool =
  if a.isNil:
    if b.isNil: return true
    return false
  elif b.isNil or a.kind != b.kind:
    return false
  else:
    case a.kind
    of P: return a.pChildren == b.pChildren
    of Br: return true
    of Text: return a.textStr == b.textStr

func fuzzTarget(x: ContentNode) =
  when defined(dumpFuzzInput): debugEcho(x)
  let data = ContentNode(kind: P, pChildren: @[
    ContentNode(kind: Text, textStr: "mychild"),
    ContentNode(kind: Br)
  ])
  doAssert x != data

defaultMutator(fuzzTarget)