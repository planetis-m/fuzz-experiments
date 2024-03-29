Tasks breakdown DRAFT
---------------------

- [X] Figure out `set[enum]`. Must work with holey enums. (1.5h) (23/7)
- [X] Port fixUtf8 to safe Nim, run tests. (1.25h) 18/7
- [X] Replace rand with a sampler, find how, make changes to the spec, write pseudocode. Failed, nested recursion can lead to SO. (3.5h) 25-26/7
- [X] Port LPM sampler, run tests. (1.0h) 27/7
- [X] Write a prototype SrcSampler that uses Any from std/typeinfo. Failed, leaks when switching branches. (1.0h) 27/7
- [X] Adjust algorithm due to recent failure, plan accordingly. (1h) 27/7
- [X] Figure out how to generalize zah's prototype. Works with custom datatypes/refs/etc (3h) 28-29/7
- [X] Add more types tables/option/etc (1h) (31/7)
- [X] Experiment with a random merge that doesn't go above sizeIncreaseHint. (2h) 31/7
- [X] r.rand(bool) is missing, so make a PR and work on adding more merge overloads and testing (1h) 31/7
- [X] Find out how to disable coverage for the fuzzers functions.
- [X] Read libFuzzer mutator's source file.
- [X] Experiment with 'read unstructured bytes then use RNG to mutate them' idea. (3h) 3/8
- [X] Experiment with the idea of filling up with zeros and ignore len/maxLen. (1h) 4/8

DONE after 4/8
==============

- [X] Fill up missing details in the spec such as distinct types, sets, refs. (2h)
- [X] Begin writing new spec/code. (2h) 30/7
- [X] Research into fuzzcheck-rs/grimoire/etc and try to find ideas worth stealing. (overengineered) (4h) 1/8-8/8
- [X] Seems like usage of sizeIncreaseHint is wrong in the seq prototype need to investigate further. (2h) 8/8
- [X] Experiment with using LibFuzzer's mutate on every type of data (result should be truncated). (1h) 8/8
- [X] Decide what would be the serialization API, should it return false on failure or fill with zeros?
- [X] Test how viable is the distinct idea, instead of having to write crazy mutators. (5h+) 9/8-10/10
- [X] Tracked down the source (libFuzzer/FuzzerLoop) for the invalid inputs. (1h) 10/8
- [X] Port the graph example. (3h) 7/8-11/8
- [X] Could port the graph example to LPM to find out how it compares. (0.75h) 13/8
- [X] Remove sanitizer coverage from the serializer, keep testing. (1h) 12/8
- [X] Use the standalone fuzzer + corpus, run them and get some perf result. (0.75h) 13/8
- [X] Find how to benchmark the mutator. (0.5h) 13/8
- [X] Find a way to fix the composition issue caused by custom mutators and pick. (1h) 12/8
- [X] Needs to check how size hints are used in LPM in sampling mutations (high priority) 13/8
- [X] Prototype with the public API, defaultMutator(typ), fuzzTarget(it, typ), customMutator(it, typ, body) (1.5h) 27/7-16/8
- [X] Implement mutator for simple objects (generic) (3h) 11/8
- [X] Write more fuzz targets (3/3) (2h)
- [X] Spent time investigating why I can't reproduce results from 2days ago. (0.75h) 14/8
- [X] Check percentage of duplicate mutations produced by the graph mutator. (0.25h) 15/8
- [X] Finish the serialization from buffer to types. (see pages 105,116) (2h) 15/8
- [X] Easy: missing byteSize overloads. 15/8
- [X] Adapt last mutation cache. (0.5h) 16/8
- [X] testOneInput parameter should be immutable, also cut more time. (2.0h) 16/8
- [X] Cleanup new code. (2h) 16/8-17/8
- [X] Step through example mutator and gain knowledge of how it works and how it can be improved. (3.0h) 17/8
- [X] Further split into procs, convert generic template into macro, and write experimental customMutator. (1.0h) 18/8
- [X] Added a post-processor step and more cleanups. (2.0h) 19/8
- [X] Need to refactor sampler/picker/mutator. (1h) 20/8
- [X] Investigate how easy it would be to add a single custom pragma "userMax".
- [X] Small refactor to prevent creating so many default values. (1h) 20/8
- [X] Correct size hint calculations and minor improvements (1.5h) 21/8
- [X] See if hashing the seq and comparing with an old hash improves performance. (1.25h) 14/8,22/8 (faster but incorrect hash for 0-len seqs due to openarray, rejected.)
- [X] Write mutators for tables. Not yet ready for v1. 22/8
- [X] Bug: post-processor shouldn't run if there is a mutate function for an object. 22/8
- [X] Add mutator overloads for seq[byte]/string and test them. (6.5h) 22/8
- [X] Missing: refs/arrays. (0.75h) 23/8
- [X] Plug-in utf8 strings (compile-time switch). 23/8
- [X] Write a macro for supporting variant objects/tuples. (2.5h) 23/8
- [X] Replace runPost fields() with macro. (0.50h) 23/8
- [X] Make the post-processor work only for objects/array/seq/string/set/ref/tuple/distinct. (1.0h) 24/8
- [X] Fix range types. (0.5h) 24/8
- [X] Safe enum/set mutator, needs a macro (try to reuse rank from enumutils). (2.5h)
- [X] Write some docs and a ref example. (0.5h) 24/8
- [X] Sets that compile to static arrays need a different solution! (1.0h) 24/8
- [X] Investigate bug in variant object example and fix crash due to cache. (1.0h) 25/8
- [X] Work on releasing drchaos and fix all bugs I know of. (3.5h) 25/8-26/8
- [X] Fixed remaining bugs and wrote a patch for nim-testutils, wrote readme, released (3.0h) 27/8-28/8


DONE after 2/9
==============

- [X] Track down and fix bug #9 (3.5h) 2/9-3/9
- [X] Work on examples and various issues (2.05h) 4/9
- [X] Add default feature, examples, debug new bugs. (6.0h) 5/9
