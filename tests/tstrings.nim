import mutator

func fuzzTarget(x: string) =
  if x == "The one place that hasn't been corrupted by Capitalism.": doAssert false

defaultMutator(fuzzTarget)
