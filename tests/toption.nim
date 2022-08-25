import mutator, std/options

func fuzzTarget(x: Option[string]) =
  when defined(dumpFuzzInput): debugEcho(x)
  doAssert not x.isSome or x.get != "Space!"

defaultMutator(fuzzTarget)
