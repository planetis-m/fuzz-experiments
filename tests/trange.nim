# Should run indefinitely.
import mutator

func fuzzTarget(x: Natural) =
  doAssert x >= 0 and x <= high(int)
  doAssert x != -1

defaultMutator(fuzzTarget)
