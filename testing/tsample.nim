import tsampler, std/typeinfo

type
  Foo = ref object
    a, b: int
    c: ref float
    d: bool
    next: Foo

var a = Foo(a: 1, b: 2, c: new(float), d: true)
var b = Foo(a: 3, b: 4, c: nil, d: true, next: Foo(c: new(float)))
b.next.c[] = 5

let ac = toAny(a.c[]) # DstSampler.sample
let bc = toAny(b.next.c[]) # SrcSampler.sample
echo ac.kind
echo bc.kind
assign(ac, bc)
echo a.c[]

type
  DestSampler = object

  Mutation* = enum
    None,
    Add,    # Adds new field with default value.
    Mutate, # Mutates field contents.
    Delete, # Deletes field.
    Copy,   # Copy values copied from another field.
    Clone   # Create new field with value copied from another.

var
  allowedMutations: set[Mutation] = {Add, Mutate, Delete, Copy, Clone}

const
  DefaultMutateWeight = 1000000

proc test(field: Any, mutation: Mutation) =
  assert(mutation != Mutation.None)
  if mutation notin allowedMutations: return
  sampler.test(DefaultMutateWeight, (field, mutation))

proc SampleImpl(message: Any; s: var Sampler[(Any, Mutation)]; r: var Rand) =
  for name, field in message.fields:
    let oneof = field->containing_oneof()
    if oneof != nil:
      # Handle entire oneof group on the first field.
      if field->index_in_oneof == 0:
        assert(oneof.field_count > 0)
        const FieldDescriptor* current_field =
            reflection->GetOneofFieldDescriptor(*message, oneof)
        while true:
          const FieldDescriptor* add_field = oneof->field(r.rand(0..oneof.field_count))
          if add_field != current_field:
            Try((message, add_field), Mutation.Add)
            Try((message, add_field), Mutation.Clone)
            break
          if oneof.field_count < 2: break
        if current_field != nil:
          if current_field->cpp_type() != FieldDescriptor::CPPTYPE_MESSAGE:
            Try((message, current_field), Mutation.Mutate)
          Try((message, current_field), Mutation.Delete)
          Try((message, current_field), Mutation.Copy)
    else:
      if field->is_repeated():
        int field_size = reflection->FieldSize(*message, field);
        size_t random_index = GetRandomIndex(random_, field_size + 1);
        Try({message, field, random_index}, Mutation.Add)
        Try({message, field, random_index}, Mutation.Clone)
        if (field_size) {
          size_t random_index = GetRandomIndex(random_, field_size);
          if (field->cpp_type() != FieldDescriptor::CPPTYPE_MESSAGE)
            Try({message, field, random_index}, Mutation.Mutate)
          Try({message, field, random_index}, Mutation.Delete)
          Try({message, field, random_index}, Mutation.Copy)
      else:
        if (reflection.HasField(message, field) or
            IsProto3SimpleField(field):
          if (field->cpp_type() != FieldDescriptor::CPPTYPE_MESSAGE)
            Try({message, field}, Mutation.Mutate)
          if not IsProto3SimpleField(field) and
              not (field.is_required and keep_initialized_):
            Try({message, field}, Mutation.Delete)
          Try({message, field}, Mutation.Copy)
        else:
          Try({message, field}, Mutation.Add)
          Try({message, field}, Mutation.Clone)
    if (field->cpp_type() == FieldDescriptor::CPPTYPE_MESSAGE) {
      if (field->is_repeated()) {
        const int field_size = reflection->FieldSize(*message, field);
        for (int j = 0; j < field_size; ++j)
          SampleImpl(reflection->MutableRepeatedMessage(message, field, j));
      } else if (reflection->HasField(*message, field)) {
        SampleImpl(reflection->MutableMessage(message, field));

