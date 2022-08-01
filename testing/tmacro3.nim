import macros

proc merge(x: var int) =
  x = 1

proc copy(x: var int) =
  x = 2

template call1(x: untyped): untyped =
  merge(x)

template call2(x: untyped): untyped =
  copy(x)

macro assign(x, call: typed): untyped =
  result = newStmtList(newCall(call, x))

var x = 0
assign(x, template call(x) = getAst(call1(x, )))
echo x
assign(x, call2)
echo x
