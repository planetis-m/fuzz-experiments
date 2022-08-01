// clang++ -fsanitize=fuzzer,address example.cc ../../src/libfuzzer/libfuzzer_macro.cc ../../src/libfuzzer/libfuzzer_mutator.cc ../../src/mutator.cc ../../src/binary_format.cc ../../src/text_format.cc ../../src/utf8_fix.cc -I../../ example.pb.cc -lprotobuf
#include <cmath>
#include <iostream>

#include "examples/libfuzzer/example.pb.h"
#include "port/protobuf.h"
#include "src/libfuzzer/libfuzzer_macro.h"

protobuf_mutator::protobuf::LogSilencer log_silincer;

template <class Proto>
using PostProcessor =
    protobuf_mutator::libfuzzer::PostProcessorRegistration<Proto>;

static PostProcessor<example::Person> reg1 = {
    [](example::Person* person, unsigned int seed) {
      person->set_id(
          std::hash<std::string>{}(person->name()));
    }};

DEFINE_BINARY_PROTO_FUZZER(const example::AddressBook& address_book) {
  // Emulate a bug.
  for (int i = 0; i < address_book.people_size(); i++) {
    const example::Person& person = address_book.people(i);
    if (person.name() == "Antonis" && person.phones_size() >= 1
        &&  person.phones(0).has_type()
        && person.phones(0).type() == example::Person_PhoneType_WORK) {
      std::cerr << person.DebugString() << "\n";
      abort();
    }
  }
}
