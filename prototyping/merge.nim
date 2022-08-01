#[
proc merge(x: var string, y: string) =
  x = y

proc merge[T](x: var seq[T], y: seq[T]; sizeIncreaseHint: int) =
  let (sizeX, sizeY) = (x.byteSize, y.byteSize)
  if sizeIncreaseHint >= sizeY and r.rand(1..3):
    x.add y
    dec(sizeIncreaseHint, x.byteSize - sizeX)
  elif sizeX + sizeIncreaseHint >= sizeY and r.rand(1..3):
    x = y
    inc(sizeIncreaseHint, sizeX - sizeY)

proc merge[T](x: var seq[T]; y: seq[T]; sizeIncreaseHint: int; r: var Rand) =
  if y.byteSize < sizeIncreaseHint and r.rand(bool): x = y

proc merge(x: var string, y: string; sizeIncreaseHint: int) =
  let (sizeX, sizeY) = (x.byteSize, y.byteSize)
  if sizeIncreaseHint >= sizeY:
    x.add y
  elif sizeX + sizeIncreaseHint >= sizeY:
    x = y

proc merge[T](x: var seq[T]; y: seq[T]; sizeIncreaseHint: int; r: var Rand) =
  var z = newSeqWith(0..y.len)
  shuffle(r, z)
  let oldSize = x.byteSize
  while x.len > 0 and r.rand(bool):
    x.delete r.rand(x.high)
  while sizeIncreaseHint > 0 and x.byteSize < oldSize + sizeIncreaseHint and r.rand(bool):
    let index = r.rand(x.len)
    x.insert(y[z.pop], index)

proc ratio*[T: SomeNumber](x: var Rand; numerator, denominator: T): bool =
  assert(0 < numerator)
  assert(numerator <= denominator)
  let x = rand(r, 1, denominator)
  result = x <= numerator

proc merge[T](x:, y: seq[T]; sizeIncreaseHint: int; r: var Rand): seq[T] =
  let (min, max) = (min(x.len, y.len), max(x.len, y.len))
  result.setLen r.rand(min..max)
  let ratio = max/min
  if
  r.ratio(min, max)

proc merge[T](x: var seq[T]; y: seq[T]; sizeIncreaseHint: int; r: var Rand) =
proc merge[T](x: var seq[T]; y: seq[T]; sizeIncreaseHint: int; r: var Rand) =
  x = x & y

  let oldLen = x.len
  let oldSize = x.byteSize
  x.setLen(oldLen+y.len)
  for i in 0..y.len-1:
    x[i+oldLen] = y[i]
  while x.len > 0 and x.byteSize < oldSize + sizeIncreaseHint and r.rand(bool):
    x.delete r.rand(x.high)

 ratio(4, 5)
let p = r.rand(0..x.high)
let q = r.rand(0..y.high)

  # var. 3
  result.setLen r.rand(min(x.len, y.len)..max(x.len, y.len))
  for i in 0..result.high:
    result[i] = merge(r.sample(x), r.sample(y), sizeIncreaseHint, r)
]#
import std/[options, tables, sets, random]

proc merge(x: var bool, y: bool; r: var Rand) =
  if r.rand(bool): x = y

proc merge(x: var char, y: char; r: var Rand) =
  if r.rand(bool): x = y

proc merge[T: SomeNumber](x: var T; y: T; r: var Rand) =
  if r.rand(bool): x = y

proc merge[T: enum](x: var T, y: T; r: var Rand) =
  if r.rand(bool): x = y

proc merge[T](x: var set[T], y: set[T]; r: var Rand) =
  if r.rand(bool): x = y

proc merge(x: var string, y: string; r: var Rand) =
  if r.rand(bool): x = y

proc merge[T](x: var seq[T]; y: seq[T]; r: var Rand) =
  for i in 0..<min(x.len, y.len):
    merge(x[i], y[i], r)

proc merge[S; T](x: var array[S, T]; y: array[S, T]; r: var Rand) =
  for i in low(x)..high(x):
    merge(x[i], y[i], r)

proc merge[T](x: var SomeSet[T], y: SomeSet[T]; r: var Rand) =
  if r.rand(bool): x = y # warning, this changes original size.

proc merge[T](x: var CountTable[T]; y: CountTable[T]; r: var Rand) =
  if y.len > 0:
    for k, v in x.mpairs:
      if k in y:
        merge(v, y[k], r)

proc merge[K, V](x: var (Table[K, V]|OrderedTable[K, V]); y: (Table[K, V]|OrderedTable[K, V]); r: var Rand) =
  if y.len > 0:
    for k, v in x.mpairs:
      if k in y:
        merge(v, y[k], r)

proc merge[T](x: var Option[T], y: Option[T]; r: var Rand) =
  if x.isSome and y.isSome: merge(x.get, y.get, r)
  #elif r.rand(bool): x = y # This would modify the length of the original!

proc merge[T](x: var ref T, y: ref T; r: var Rand) =
  if x != nil and y != nil: merge(x[], y[], r)

proc merge[T: object|tuple](x: var T, y: T; r: var Rand) =
  for v1, v2 in fields(x, y):
    merge(v1, v2, r)

type
  Foo = object
    a, b: int
    c: ref float
    d: bool
    e: seq[int]
    next: ref Foo

proc `$`(x: ref Foo): string = $x[]

proc main =
  var a = (ref Foo)(a: 1, b: 2, c: new(float), d: true, next: (ref Foo)(a: 10, c: nil, d: false))
  var b = (ref Foo)(a: 3, b: 4, c: nil, d: false, next: (ref Foo)(a: 8, c: new(float), b: 9, d: true), e: @[4, 5, 6])
  b.next.c[] = 5
  #var a, b = toTable({'a': 1, 'b': 2})
  merge(a, b, randState)
  echo a

main()
