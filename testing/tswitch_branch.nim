type
  Fruit = enum
    Apple, Banana, Orange
  Bar = object
    b: bool
    case kind: Fruit
    of Banana, Orange:
      bad: string
      banana: int
    of Apple: apple: int
    a: string

proc switch_branch(x: var Bar; kind: Fruit) {.exportc.} =
  #case x.kind
  #of Banana, Orange:
    #if kind notin {Banana, Orange}:
      #`=destroy`(x.bad)
      #wasMoved(x.bad)
      #`=destroy`(x.banana)
      #wasMoved(x.banana)
  #of Apple:
    #if kind != Apple:
      #`=destroy`(x.apple)
      #wasMoved(x.apple)
  {.cast(uncheckedAssign).}:
    x.kind = kind
#[
proc main =
  var x = Bar(b: true, kind: Orange, bad: "bug!", a: "nobug!")
  prepareMutation(x.a)
  prepareMutation(x.bad)
  switch_branch(x, Banana)
  echo x.bad
  switch_branch(x, Apple)
  echo x.apple

main()]#
