import mutator, random

type
  X = distinct float

proc `==`(a, b: X): bool {.borrow.}

proc postProcess(x: var X; r: var Rand) =
  x = X(100)

func fuzzTarget(x: X) =
  if x == X(100):
    doAssert false

defaultMutator(fuzzTarget)
