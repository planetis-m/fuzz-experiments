# Compile with: nim c --cc:clang --mm:arc --threads:off --panics:on -d:useMalloc -t:"-fsanitize=address,undefined" -l:"-fsanitize=address,undefined" -d:danger -d:fuzzer -d:fuzz_sa -g bench_graph.nim
import std/[os, strformat, strutils]
include fuzz_graph

proc standaloneFuzzTarget =
  ## Standalone main procedure for fuzz targets.
  ##
  ## Use `-d:fuzzSa` to call `standaloneFuzzTarget` to provide reproducers
  ## for bugs when linking against libFuzzer is undesirable.
  #stderr.write &"StandaloneFuzzTarget: running {paramCount()} inputs\n"
  #discard initialize()
  for k in walkDir("graph_corpus"):
    #stderr.write &"Running: {k.path}\n"
    var buf = readFile(k.path)
    discard testOneInput(cast[ptr UncheckedArray[byte]](cstring(buf)), buf.len)
    #stderr.write &"Done:    {k.path}: ({formatSize(buf.len)})\n"

standaloneFuzzTarget()
