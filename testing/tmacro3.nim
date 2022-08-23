import macros

proc merge(x: var int; y: int, z: bool) =
  x = 1

proc copy(x: var int; y: float) =
  x = 2

template call1(x: untyped): untyped =
  merge(x, b, c)

template call2(x: untyped): untyped =
  copy(x, a)

macro assign(x: typed, call: untyped): untyped =
  result = newStmtList(newCall(call, x))
  echo result.treeRepr

proc foo(x: var int) =
  let
    a = 1.0
    b = 2
    c = true
  #assign(x, template call(x) = getAst(call1(x, )))
  echo x
  assign(x, call2)
  echo x

var x = 0
foo(x)
