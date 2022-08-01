type
  Foo = ref object
    a, b: int
    c: ref float
    d: bool
    next: Foo

# noop
#proc clone[U](x: var int; y: U) = discard
#proc clone[U](x: var float; y: U) = discard
#proc clone[U](x: var bool; y: U) = discard
#proc clone[T; U](x: var ref T; y: U) = discard

proc clone(x: var int; y: int) = x = y
proc clone(x: var float; y: float) = x = y
proc clone(x: var bool; y: bool) = x = y
proc clone[T](x: var ref T; y: ref T) = x = y

proc getSrc[T](x: var T; y: int; count: var int; typ: string) =
  if typ == $typeof(y):
    dec count
    if count == 0:
      when compiles(clone(x, y)):
        clone(x, y)
      return
proc getSrc[T](x: var T; y: float; count: var int; typ: string) =
  if typ == $typeof(y):
    dec count
    if count == 0:
      when compiles(clone(x, y)):
        clone(x, y)
      return
proc getSrc[T](x: var T; y: bool; count: var int; typ: string) =
  if typ == $typeof(y):
    dec count
    if count == 0:
      when compiles(clone(x, y)):
        clone(x, y)
      return
proc getSrc[T; U](x: var T; y: ref U; count: var int; typ: string) =
  if typ == $typeof(y):
    dec count
    if count == 0:
      when compiles(clone(x, y)):
        clone(x, y)
      return
  if y != nil:
    getSrc(x, y[], count, typ)
proc getSrc[T; U: object](x: var T; y: U; count: var int; typ: string) =
  #if typ == $typeof(y):
    #if count == 0:
      #when compiles(clone(x, y)):
        #clone(x, y)
      #return
    #dec count
  for v in fields(y):
    getSrc(x, v, count, typ)
    if count == 0: return

proc getDest[U](x: var int; count1: var int; y: U; count2: var int; typ: string) =
  if count1 == 0:
    getSrc(x, y, count2, typ)
  else: dec count1
proc getDest[U](x: var float; count1: var int; y: U; count2: var int; typ: string) =
  if count1 == 0:
    getSrc(x, y, count2, typ)
  else: dec count1
proc getDest[U](x: var bool; count1: var int; y: U; count2: var int; typ: string) =
  if count1 == 0:
    getSrc(x, y, count2, typ)
  else: dec count1
proc getDest[T; U](x: var ref T; count1: var int; y: U; count2: var int; typ: string) =
  if count1 == 0:
    getSrc(x, y, count2, typ)
    return
  dec count1
  if x != nil:
    getDest(x[], count1, y, count2, typ)
proc getDest[T: object; U](x: var T; count1: var int; y: U; count2: var int; typ: string) =
  #if count1 == 0:
    #getSrc(x, y, count2, typ)
    #return
  #dec count1
  for v in fields(x):
    getDest(v, count1, y, count2, typ)
    if count1 == 0: return

var a = Foo(a: 1, b: 2, c: new(float), d: true)
var b = Foo(a: 3, b: 4, c: nil, d: true, next: Foo(c: new(float)))
b.next.c[] = 5

var ac = 4 # This is the number obtained from the DstSampler.sample
let typ = "float"
var bc = 1 # This is the number obtained from the SrcSampler.sample
getDest(a, ac, b, bc, typ) # mutual recursion
echo a.c[]

#type
  #Result = object
    #typ: string
    #a, b: int
#[
proc assign[T: object, U](x: var T; y: U; res: var Result)
  for v in fields(x):
    assign(v, assign(x, u, res), res)]#

# Getsrc 30, getdst 6, 800 lines
# 20
