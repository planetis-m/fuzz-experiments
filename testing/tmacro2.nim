import macros

proc merge(x: var int) =
  x = 1

proc copy(x: var float) =
  x = 2.0

template call(x: int): untyped =
  merge(x)

template call(x: float): untyped =
  copy(x)

macro assign(x: typed): untyped =
  template interf(x): untyped = bindSym(x, brForceOpen)
  result = newStmtList(newCall(interf"call", x))

var x = 0
assign(x)
echo x
var y = 0.0
assign(y)
echo y
