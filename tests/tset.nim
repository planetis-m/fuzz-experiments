import mutator

func fuzzTarget(x: set[char]) =
  doAssert x != {'a'..'z'}

defaultMutator(fuzzTarget)
