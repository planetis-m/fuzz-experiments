// clang++ -std=c++17 -fsanitize=fuzzer,address graph.cc ../../src/libfuzzer/libfuzzer_macro.cc ../../src/libfuzzer/libfuzzer_mutator.cc ../../src/mutator.cc ../../src/binary_format.cc ../../src/text_format.cc ../../src/utf8_fix.cc -I../../ graph.pb.cc -lprotobuf
#include <cmath>
#include <iostream>
#include <algorithm>

#include "examples/libfuzzer/graph.pb.h"
#include "port/protobuf.h"
#include "src/libfuzzer/libfuzzer_macro.h"

protobuf_mutator::protobuf::LogSilencer log_silencer;

template <class Proto>
using PostProcessor =
protobuf_mutator::libfuzzer::PostProcessorRegistration<Proto>;

static PostProcessor<graph::Graph::Node> reg1 = {
  [](graph::Graph::Node* node, unsigned int seed) {
    node->set_data(
      std::clamp(node->data(), -128, 127));
  }
};

DEFINE_BINARY_PROTO_FUZZER(const graph::Graph& graph) {
  // Emulate a bug.
  if (graph.nodes_size() == 8 &&
    graph.nodes(0).data() == 63 &&
    graph.nodes(1).data() == 3 &&
    graph.nodes(2).data() == -56 &&
    graph.nodes(3).data() == 100 &&
    graph.nodes(4).data() == -100 &&
    graph.nodes(5).data() == -78 &&
    graph.nodes(6).data() == 46 &&
    graph.nodes(7).data() == 120 &&

    graph.nodes(0).edges_size() == 2 &&
    graph.nodes(0).edges(0) == 1 &&
    graph.nodes(0).edges(1) == 2 &&
    graph.nodes(1).edges_size() == 2 &&
    graph.nodes(1).edges(0) == 3 &&
    graph.nodes(1).edges(1) == 4 &&
    graph.nodes(2).edges_size() == 2 &&
    graph.nodes(2).edges(0) == 5 &&
    graph.nodes(2).edges(1) == 6 &&
    graph.nodes(3).edges_size() == 1 &&
    graph.nodes(3).edges(0) == 7 &&
    graph.nodes(4).edges_size() == 0 &&
    graph.nodes(5).edges_size() == 0 &&
    graph.nodes(6).edges_size() == 0 &&
    graph.nodes(7).edges_size() == 0) {
    std::cerr << graph.DebugString() << "\n";
    abort();
    }
}
