import mutator

func fuzzTarget(x: seq[bool]) =
  if x == @[true, false, true, true, false, true]: doAssert false

defaultMutator(fuzzTarget)
