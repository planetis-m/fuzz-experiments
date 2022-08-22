import mutator, tablesexpapi

func fuzzTarget(x: OrderedTable[int, int]) =
  when defined(dumpFuzzInput): debugEcho(x)
  if x.len == 8 and
      0 in x and x[0] == 63 and
      1 in x and x[1] == 3 and
      2 in x and x[2] == -56 and
      3 in x and x[3] == 100 and
      4 in x and x[4] == -100:
    doAssert false

defaultMutator(fuzzTarget)
