import mutator

type
  Foo = object
    a: string
    case kind: bool
    of true:
      b: string
    else:
      c: int

func fuzzTarget(x: Foo) =
  if x.a.len == 50 and x.kind and x.b.len == 100:
    doAssert false

defaultMutator(fuzzTarget)
