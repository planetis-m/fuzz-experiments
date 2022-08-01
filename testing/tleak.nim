import std/typeinfo

type
  Foo = enum
    a, b
  Bar = object
    case kind: Foo
    of a: s: string
    of b: i: int

proc main =
  var y = Bar(kind: a, s: "hello")
  prepareMutation(y.s)
  {.cast(uncheckedAssign).}:
    let x = toAny(y.kind)
  echo x.kind
  setBiggestInt(x, b.ord)
  echo y.kind

main()
