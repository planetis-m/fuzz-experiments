import mutator

func fuzzTarget(x: int) =
  raise newException(ValueError, "Fuzzer test 1")

defaultMutator(fuzzTarget)
