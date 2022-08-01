type
  Trace = seq[Action]
  ActionKind = enum
    kPushBack, kPopBack, kBack, kPushFront, kPopFront, kFront, kLen
  Action = object
    case kind: ActionKind
    of kPushBack, kPushFront: val: int
    else: discard

type
  Deque = object
    seq[array[3, int]]

proc pushBack(x: var Deque; val: int)
proc popBack(x: var Deque)
proc back(x: Deque): int

proc pushFront(x: var Deque; val: int)
proc popFront(x: var Deque)
proc font(x: Deque): int

proc len(x: Deque): int {.inline.}

fuzzTarget(actions, Trace):
  when defined(dumpFuzzInput): echo x
  var d: Deque
  var queue: seq[int]
  for a in actions:
    case a
    of kPushBack:
      d.pushBack(a.val)
      queue.add a.val
    of kPopBack:
      d.popBack
      discard queue.pop
    of kBack: assert d.back == queue[^1]
    of kPushFront:
      d.pushFront(a.val)
      queue.insert(a.val, 0)
    of kPopFront:
      d.popFront
      delete(queue, 0)
    of kFront: assert d.front == queue[0]
    of kLen: assert d.len == queue.len
