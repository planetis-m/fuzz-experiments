# Should hang.
import mutator

type
  Color = enum
    Red, Green, Blue

func fuzzTarget(x: Color) =
  doAssert x.ord >= low(Color).ord and x.ord <= high(Color).ord
  doAssert x.ord != -1

defaultMutator(fuzzTarget)
