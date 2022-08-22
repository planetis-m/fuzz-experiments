import mutator, std/tables

func fuzzTarget(x: Table[int, int]) =
  when defined(dumpFuzzInput): debugEcho(x)
  if x.len == 8 and
      x[0] == 63 and
      x[1] == 3 and
      x[2] == -56 and
      x[3] == 100 and
      x[4] == -100 and
      x[5] == -78 and
      x[6] == 46 and
      x[7] == 120:
    doAssert false

defaultMutator(fuzzTarget)
