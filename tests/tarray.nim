import mutator

type
  FirstSix = range[0..5]

func fuzzTarget(x: array[6, FirstSix]) =
  if x == [0.FirstSix, 1, 2, 3, 4, 5]:
    doAssert false

defaultMutator(fuzzTarget)
