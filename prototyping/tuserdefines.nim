import random, macros

#template repeatMutate(call: untyped) = discard
#proc mutateSeq[T](value: sink seq[T]; userMax: Natural; sizeIncreaseHint: int, r: var Rand): seq[T] = discard

#template defineMutator(value: untyped, typ: typedesc, body: untyped) =
  #proc mutate(value: var typ; sizeIncreaseHint: Natural; r: var Rand) =
    #body
  #template hasMutator(t: typedesc[typ]): bool = true

#defineMutator(x, seq[int]):
  #repeatMutate(mutateSeq(x, high(int), sizeIncreaseHint, r))

#defineMutator(x, seq[Foo[T]]): # how?
  #repeatMutate(mutateSeq(x, high(int), sizeIncreaseHint, r))

type
  Foo[T] = object
    x: T

#macro isOverloaded(x: typed): bool =
  #expectKind(x, nnkCall)
  #expectMinLen(x, 1)
  #let params = getTypeImpl(x[0])[0]
  #echo getType(x[0]).getTypeImpl.treeRepr
  #expectKind params, nnkFormalParams
  #echo params.treeRepr
  #result = newLit(true)

proc mutate[T: object](x: var T) = echo "T: object"
proc mutate[T](x: var Foo[T]) = echo "Foo[T]"
#proc mutate(x: var Foo[int]) = echo "Foo[int]"

#var x: Foo[int]
#foo(x)
# For the first proc it outputs:
#ProcTy
  #FormalParams
    #Empty
    #IdentDefs
      #Sym "x"
      #BracketExpr
        #Sym "Foo"
        #Sym "int"
      #Empty
  #Empty
# Second:
#ProcTy
  #FormalParams
    #Empty
    #IdentDefs
      #Sym "x"
      #BracketExpr
        #Sym "Foo"
        #BracketExpr
          #Sym "Foo"
          #Sym "int"
      #Empty
  #Empty

#FormalParams
  #Empty
  #IdentDefs
    #Sym "x"
    #BracketExpr
      #Sym "Foo"
      #Sym "int"
    #Empty

# but when both are uncommented, it just returns void:
#Sym "void"

# xigoi's suggestion https://forum.nim-lang.org/t/9364#61494
template hasCustomMutImpl(x): bool =
  `not`: compiles:
    proc mutate(_: var typeof(x)) = discard
    mutate(x)

var x: Foo[int]
echo hasCustomMutImpl(x)
mutate(x)
