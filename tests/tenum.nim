# Should hang.
import mutator

type
  Color = enum
    Red, Green, Blue
  OtherColor = enum
    Cyan, Magenta=2, Yellow=4, Black=8

func fuzzTarget(x: OtherColor) =
  #doAssert x.ord >= low(Color).ord and x.ord <= high(Color).ord
  #doAssert x.ord != -1
  doAssert x in [Cyan, Magenta, Yellow, Black]

defaultMutator(fuzzTarget)
