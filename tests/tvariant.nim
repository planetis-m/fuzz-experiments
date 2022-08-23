import mutator

type
  Foo = object
    a: int
    case kind: bool
    of true:
      b: string
    else:
      c: int

func fuzzTarget(x: Foo) =
  if x.kind and x.a == 1 and x.b.len == 100:
    doAssert false

defaultMutator(fuzzTarget)
