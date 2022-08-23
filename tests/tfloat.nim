import mutator

func fuzzTarget(x: float) =
  if x == 100.0:
    doAssert false

defaultMutator(fuzzTarget)
