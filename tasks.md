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

TODO
====

- [ ] See if hashing the seq and comparing with an old hash improves performance. (1.25h+) 14/8-
- [ ] Write mutators for tables. Do we need experimental tables API that returns the index?
- [ ] Write a macro for supporting variant objects.
- [ ] Safe enum/range mutator, needs a macro (try to reuse rank from enumutils). (1h)
- [ ] Write some docs and a ref example.

MAYBE
=====

- [ ] Step though LPM graph example to understand how it handles nested messages mutation.
- [ ] Experiment with mutate having dest and source parameters, might fix performance issue and allow crossover. (this is a good idea.)
- [ ] Experiment with the idea of trying to mutate everything at once. (might not work well)
- [ ] See if the original graph mutator performs any better than the 'dumb' one. (sure it does.)

POSTPONED after first release
=============================

- [ ] Work on two prototypes, one with 'recombine' + mutate other with merge + combine + mutate (low priority)
- [ ] Write mutate overloads for most types + merge.
- [ ] Idea: use minification as a way to 'benchmark' difference between only customMutator or together with crossover
