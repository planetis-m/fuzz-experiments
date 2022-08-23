import mutator

func fuzzTarget(x: ref seq[byte]) =
  if x[] == @[0x3f.byte, 0x2e, 0x1d, 0x0c]:
    doAssert false

defaultMutator(fuzzTarget)
