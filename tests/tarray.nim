import mutator

func fuzzTarget(x: array[5, int]) =
  if x == [1, 2, 3, 4, 5]:
    doAssert false

defaultMutator(fuzzTarget)
