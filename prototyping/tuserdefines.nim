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

macro isOverloaded(x: typed): bool =
  let params = getTypeInst(x)[0]
  expectKind params, nnkFormalParams
  echo params.treeRepr
  #expectKind(procInst, nnkProcDef)
  #expectLen(inst[])
  #result = newLit(getTypeInst(x))
  result = newLit(true)

proc foo[T: object](x: T) = echo "true"
proc foo[T](x: Foo[T]) = echo "false"

#var x: Foo[int]
#foo(x)
echo isOverloaded(foo[int]) # well shit
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

# but when both are uncommented, it just returns void:
#Sym "void"
