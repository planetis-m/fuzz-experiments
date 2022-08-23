# Should not leak, crash or the address sanitizer complain. Is the dictionary limit ~64bytes?
import mutator, random

type
  Foo = object
    a: string
    case kind: bool
    of true:
      b: string
    else:
      c: int

proc postProcess(x: var bool; r: var Rand) =
  x = true

func fuzzTarget(x: Foo) =
  if x.a == "The one place that hasn't been corrupted by Capitalism." and x.kind and x.b == "Space!":
    doAssert false

defaultMutator(fuzzTarget)
