#[
proc combine[T: object; U: object](a: var T, b: var U; depth: int; reverse = false) =
  for v1 in fields(a):
    for v2 in fields(b):
      when v2 is object|tuple:
        combine(a, v2, depth, true)
      elif v1 is object|tuple:
        combine(v1, b, depth)
      elif typeof(v1) == typeof(v2):
        if reverse: v2 = v1
        else: v1 = v2

proc combine[T; U](a: ref T, b: U; depth: int; reverse = false) =
  if depth < 200: discard
  else: combine(a[], b, depth + 1)]#

#proc combine(x: var Foo, y: var int, res: int, reverse = false) =
  #case res
  #of 3:
    #if reverse: y = x.a
    #else: x.a = y
  #of 4:
    #if reverse: y = x.b
    #else: x.b = y
  #of 5:

#proc combine(x, y: var Foo, res: int, reverse = false) =
  #case res
  #of 0:
    #if reverse: y.a = x.a
    #else: x.a = y.a
  #of 1:
    #if reverse: y.a = x.b
    #else: x.a = y.b
  #of 2:
    #if reverse: #??
    #combine(y.next, x.a, res, true)

#macro combineImpl(x, y, depth, res: typed) =
  # macro logic pseudocode
  #for v1 in fields(a):
    #for v2 in fields(b):
      #quote do:
        #when v2 is object|tuple:
          #if depth < 200: discard
          #else: combine(a, v2, depth, res)
        #elif v1 is object|tuple:
          #if depth < 200: discard
          #else: combine(v1, b, depth, res)
        #elif typeof(v1) == typeof(v2):
          #v1 = v2
#proc combine[T; U](x: var T, y: U, depth: int, res: int) =
  #combineImpl(x, y, depth, res)

type
  Foo = object
    a, b: int
    c: ref float
    d: bool
    e: seq[int]
    next: ref Foo

template select(body: untyped) =
  dec res
  if res == 0:
    writeStackTrace()
    echo astToStr body
    body
    return

proc combine(x: var bool, y: bool, depth: int, res: var int) =
  if res > 0: select: x = y

proc combine(x: var int, y: int, depth: int, res: var int) =
  if res > 0: select: x = y

proc combine(x: var float, y: float, depth: int, res: var int) =
  if res > 0: select: x = y

proc combine(x: var Foo, y: Foo, depth: int, res: var int)

proc combine[T; U: not ref](x: var ref T; y: U, depth: int, res: var int) =
  if depth <= 20 and x != nil:
    combine(x[], y, depth+1, res)

proc combine[T: not ref; U](x: var T; y: ref U, depth: int, res: var int) =
  if depth <= 20 and y != nil:
    combine(x, y[], depth+1, res)

proc combine[T; U](x: var ref T; y: ref U, depth: int, res: var int) =
  if depth <= 20 and x != nil and y != nil:
    combine(x[], y[], depth+1, res)

proc combine[T; U](x: var seq[T], y: U, depth: int, res: var int) =
  if depth <= 20:
    for i in 0..<x.len: combine(x[i], y, depth+1, res)

proc combine[T; U](x: var T; y: seq[U], depth: int, res: var int) =
  if depth <= 20:
    for i in 0..<y.len: combine(x, y[i], depth+1, res)

proc combine[T; U](x: var seq[T]; y: seq[U], depth: int, res: var int) =
  if depth <= 20:
    for i in 0..<x.len:
      for j in 0..<y.len:
        combine(x[i], y[j], depth+1, res)

proc combine(x: var bool, y: Foo, depth: int, res: var int) =
  combine(x, y.d, depth, res)
  when compiles(combine(x, y.c, depth, res)): combine(x, y.c, depth, res)
  #combine(x, y.e, depth, res)
  combine(x, y.next, depth, res)

proc combine(x: var float, y: Foo, depth: int, res: var int) =
  combine(x, y.c, depth, res)
  combine(x, y.next, depth, res)

proc combine(x: var int, y: Foo, depth: int, res: var int) =
  combine(x, y.a, depth, res)
  combine(x, y.b, depth, res)
  when compiles(combine(x, y.c, depth, res)): combine(x, y.c, depth, res)
  when compiles(combine(x, y.e, depth, res)): combine(x, y.e, depth, res)
  combine(x, y.next, depth, res)

proc combine(x: var Foo, y: Foo, depth: int, res: var int) =
  combine(x.a, y, depth, res)
  combine(x.b, y, depth, res)
  combine(x.d, y, depth, res)
  combine(x.c, y, depth, res)
  combine(x.e, y, depth, res)
  combine(x.next, y, depth, res)

proc `$`[T](x: ref T): string =
  if x != nil: result = $x[]

var a = (ref Foo)(a: 1, b: 2, c: new(float), d: true, next: (ref Foo)(a: 10, c: nil, d: false))
var b = Foo(a: 3, b: 4, c: nil, d: false, next: (ref Foo)(a: 8, c: new(float), b: 9, d: true))
b.next.c[] = 5

var res = 21
combine(a, b, 0, res)
echo a
echo res
