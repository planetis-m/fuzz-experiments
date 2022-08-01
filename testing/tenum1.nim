import strutils, std/setutils

type
  Foo = enum
    a = 1, b = 2, c, d, e = 7, f, g = 10

const size = sizeof(set[Foo])*8
var x: set[Foo] = {low(Foo)..high(Foo)}
echo toBin(cast[int](x), size) # 0000001111111111
x = {a..g}
echo toBin(cast[int](x), size) # 0000001111111111
x = {}
x.incl a
x.incl b
x.incl c
x.incl d
x.incl e
x.incl f
x.incl g
echo toBin(cast[int](x), size) # 0000001011001111
x = fullSet(Foo)
echo toBin(cast[int](x), size)
