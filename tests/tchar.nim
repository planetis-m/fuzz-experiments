import mutator

#func fuzzTarget(x: char) =
  #if x == 'a': doAssert false

func fuzzTarget(x: bool) =
  if x == true: doAssert false

defaultMutator(fuzzTarget)
