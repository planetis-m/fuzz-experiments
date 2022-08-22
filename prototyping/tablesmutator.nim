import random
include std/tables

proc firstPositionHidden*[A, B](t: OrderedTable[A, B]): int =
  ## Undocumented API for iteration. Used by the JSON module.
  if t.counter > 0:
    result = t.first
    while result >= 0 and not isFilled(t.data[result].hcode):
      result = t.data[result].next
  else:
    result = -1

proc nextPositionHidden*[A, B](t: OrderedTable[A, B]; current: int): int =
  ## Undocumented API for iteration. Used by the JSON module.
  result = t.data[current].next
  while result >= 0 and not isFilled(t.data[result].hcode):
    result = t.data[result].next

proc pairAtHidden*[A, B](t: OrderedTable[A, B]; current: int): (A, B) {.inline.} =
  ## Undocumented API for iteration. Used by the JSON module.
  result = (t.data[current].key, t.data[current].val)

proc positionAtHidden*[A, B](t: OrderedTable[A, B]; index: int): int =
  var index = index
  result = firstPositionHidden(t)
  while index > 0:
    result = t.nextPositionHidden(result)
    dec index

proc newInput*[T](sizeIncreaseHint: int; r: var Rand): T = discard
proc runMutator*[T](x: var T; sizeIncreaseHint: int; enforceChanges: bool; r: var Rand) = discard

proc mutateTab*[A, B](value: var OrderedTable[A, B]; previous: OrderedTable[A, B]; userMax, sizeIncreaseHint: int;
    r: var Rand): bool =
  let previousSize = previous.byteSize
  while value.len > 0 and r.rand(bool):
    let pos = positionAtHidden(value, rand(r, value.high))
    assert pos >= 0
    let (key, _) = value.pairAtHidden(pos)
    value.del(key)
  var currentSize = value.byteSize
  template remainingSize: untyped = sizeIncreaseHint-currentSize+previousSize
  while value.len < userMax and remainingSize > 0 and r.rand(bool):
    let key = newInput[A](remainingSize, r)
    currentSize = value.byteSize
    value[key] = newInput[B](remainingSize, r)
    currentSize = value.byteSize
  if value != previous:
    result = true
  elif value.len == 0:
    let key = newInput[A](remainingSize, r)
    currentSize = value.byteSize
    value[key] = newInput[B](remainingSize, r)
    result = value != previous
  else:
    let pos = positionAtHidden(value, rand(r, value.high))
    assert pos >= 0
    let (key, _) = value.pairAtHidden(pos)
    runMutator(value[key], remainingSize, true, r)
    result = value != previous
