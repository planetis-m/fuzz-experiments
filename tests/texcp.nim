# Make sure we catch the exception and it doesn't leak any memory.
import mutator

func fuzzTarget(x: int) =
  raise newException(ValueError, "Fuzzer test 1")

defaultMutator(fuzzTarget)
