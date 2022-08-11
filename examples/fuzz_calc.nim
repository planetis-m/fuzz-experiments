# Example from https://www.youtube.com/watch?v=wTWNmOSKfD4
import math

type
  Const = object
    val: int

  BinaryOpKind = enum
    kPlus, kMinus, kMul, kDiv, kMod
  BinaryOp = object
    kind: BinaryOpKind
    left, right: Expr

  UnaryOpKind = enum
    kAbs, kSqrt
  UnaryOp = object
    kind: UnaryOpKind
    arg: Expr

  ExprKind = enum
    kConst, kBinaryOp, kUnaryOp
  Expr = ref object
    case kind: ExprKind
    of kConst: constant: Const
    of kUnaryOp: unop: UnaryOp
    of kBinaryOp: binop: BinaryOp

proc `$`(e: Expr): string {.inline.} = $e[]

proc eval(e: Expr): int =
  #if e == nil: return 0
  case e.kind
  of kConst: result = e.constant.val
  of kUnaryOp:
    let evaldArg = eval(e.unop.arg)
    case e.unop.kind
    of kAbs: result = if evaldArg < 0: -evaldArg else: evaldArg #UB low(int)
    of kSqrt: result = int sqrt(evaldArg.float)
  of kBinaryOp:
    let
      evaldLeft = eval(e.binop.left)
      evaldRight = eval(e.binop.right)
    case e.binop.kind
    of kPlus: result = evaldLeft + evaldRight
    of kMinus: result = evaldLeft - evaldRight
    of kMul: result = evaldLeft * evaldRight
    of kDiv:
      #if evaldRight == 0: raise newExpeption(ValueError, "")
      result = evaldLeft div evaldRight
    of kMod:
      #if evaldRight == 0: raise newExpeption(ValueError, "")
      result = evaldLeft mod evaldRight

fuzzTarget(x, Expr):
  when defined(dumpFuzzInput): echo x
  try: eval(x)
  except: discard

#let x = Expr(kind: kUnaryOp, unop: UnaryOp(kind: kAbs, arg: Expr(kind: kConst, constant: Const(val: 2))))
#echo x
#echo eval(x)
