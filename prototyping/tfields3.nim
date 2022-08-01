import std/[options, tables, sets]

template select(body: untyped) =
  if res > 0:
    dec res
    if res == 0:
      echo astToStr(body)
      body

proc combine(x: var bool, y: bool, depth: int, res: var int) {.inline.} =
  select: x = y

proc combine(x: var char, y: char, depth: int, res: var int) {.inline.} =
  select: x = y

proc combine[T: SomeNumber](x: var T, y: T, depth: int, res: var int) {.inline.} =
  select: x = y

proc combine[T: enum](x: var T, y: T, depth: int, res: var int) {.inline.} =
  select: x = y

proc combine[T](x: var set[T], y: set[T], depth: int, res: var int) {.inline.} =
  select: x = y

proc combine(x: var string, y: string, depth: int, res: var int) {.inline.} =
  select: x = y

proc combine[S, T; U: not array](x: var array[S, T], y: U, depth: int, res: var int) {.inline.} =
  for i in low(x)..high(x):
    when compiles(combine(x[i], y, depth, res)): combine(x[i], y, depth, res)

proc combine[T; S, U](x: var T, y: array[S, U], depth: int, res: var int) {.inline.} =
  for i in low(y)..high(y):
    when compiles(combine(y[i], y, depth, res)): combine(y[i], y, depth, res)

proc combine[T](x: var SomeSet[T], y: SomeSet[T], depth: int, res: var int) {.inline.} =
  select: x = y

proc combine[T; U: not CountTable](x: var CountTable[T], y: U, depth: int, res: var int) {.inline.} =
  if depth <= 20:
    for v in x.mitems:
      when compiles(combine(v, y, depth+1, res)): combine(v, y, depth+1, res)

proc combine[T; U](x: var T, y: CountTable[U], depth: int, res: var int) {.inline.} =
  if depth <= 20:
    for v in y.items:
      when compiles(combine(x, v, depth+1, res)): combine(x, v, depth+1, res)

proc combine[K, V; U: not (Table|OrderedTable)](x: var (Table[K, V]|OrderedTable[K, V]), y: U, depth: int, res: var int) {.inline.} =
  if depth <= 20:
    for v in x.mitems:
      when compiles(combine(v, y, depth+1, res)): combine(v, y, depth+1, res)

proc combine[T; K, V](x: var T, y: (Table[K, V]|OrderedTable[K, V]), depth: int, res: var int) {.inline.} =
  if depth <= 20:
    for v in y.items:
      when compiles(combine(x, v, depth+1, res)): combine(x, v, depth+1, res)

proc combine[T; U: not Option](x: var Option[T], y: U, depth: int, res: var int) {.inline.} =
  if isSome(x):
    when compiles(combine(x.get, y, depth, res)): combine(x.get, y, depth, res)

proc combine[T; U](x: var T, y: Option[U], depth: int, res: var int) {.inline.} =
  if isSome(y):
    when compiles(combine(x, y.get, depth, res)): combine(x, y.get, depth, res)

proc combine[T; U: not ref](x: var ref T; y: U, depth: int, res: var int) {.inline.} =
  if depth <= 20 and x != nil:
    when compiles(combine(x[], y, depth+1, res)): combine(x[], y, depth+1, res)

proc combine[T; U](x: var T; y: ref U, depth: int, res: var int) {.inline.} =
  if depth <= 20 and y != nil:
    when compiles(combine(x, y[], depth+1, res)): combine(x, y[], depth+1, res)

proc combine[T; U: not seq](x: var seq[T], y: U, depth: int, res: var int) {.inline.} =
  if depth <= 20:
    for i in 0..<x.len:
      when compiles(combine(x[i], y, depth+1, res)): combine(x[i], y, depth+1, res)

proc combine[T; U](x: var T; y: seq[U], depth: int, res: var int) {.inline.} =
  if depth <= 20:
    for i in 0..<y.len:
      when compiles(combine(x, y[i], depth+1, res)): combine(x, y[i], depth+1, res)

proc combine[T: object|tuple; U: not object|tuple](x: var T, y: U, depth: int, res: var int) {.inline.} =
  for v in fields(x):
    when compiles(combine(v, y, depth, res)): combine(v, y, depth, res)

proc combine[T; U: object|tuple](x: var T, y: U, depth: int, res: var int) {.inline.} =
  for v in fields(y):
    when compiles(combine(x, v, depth, res)): combine(x, v, depth, res)

type
  Foo = object
    a, b: int
    c: ref float
    d: bool
    e: seq[int]
    next: ref Foo

  FuzzInt = distinct int
  A = object
    s: string
    i: FuzzInt
    b: B
    i2: float
    s2: ref string

  B = object
    f: Option[float]
    r: ref B
    s: string

proc combine(x: var FuzzInt, y: FuzzInt, depth: int, res: var int) {.borrow.}

proc main =
  #var a = (ref Foo)(a: 1, b: 2, c: new(float), d: true, next: (ref Foo)(a: 10, c: nil, d: false))
  #var b = Foo(a: 3, b: 4, c: nil, d: false, next: (ref Foo)(a: 8, c: new(float), b: 9, d: true), e: @[4, 5, 6])
  #b.next.c[] = 5

  var res = 7
  #var
    #a = @[@[1, 2], @[3, 4]]
    #b = @[@[5, 6], @[7, 8]]
  var
    a, b: A
  a.i = 1.FuzzInt
  a.i2 = 2
  a.s = "abc"
  a.b.f = some(10.0)
  a.b.s = "def"
  combine(a, b, 0, res)
  echo a
  echo res

main()
