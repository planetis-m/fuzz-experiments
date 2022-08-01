import ".."/arbitrary, std/random

type
  #Foo = distinct int32
  Foo {.size: sizeof(int32).} = enum
    A0 = 0
    B1 = 1
    C2 = 2
    D3 = 3
    E4 = 4
    F5 = 5
    G6 = 6
    H7 = 7
    I8 = 8
    J9 = 9
    K10 = 10
    L11 = 11
    M12 = 12
    N13 = 13
    O14 = 14
    P15 = 15
    Q16 = 16
    R17 = 17
    S18 = 18
    T19 = 19
    U20 = 20
    V21 = 21
    W22 = 22
    X23 = 23
    Y24 = 24
    Z25 = 25
    A26 = 26
    B27 = 27
    C28 = 28
    D29 = 29
    E30 = 30
    F31 = 31
    G32 = 32
    H33 = 33
    I34 = 34
    J35 = 35
    K36 = 36
    L37 = 37
    M38 = 38
    N39 = 39
    O40 = 40
    P41 = 41
    Q42 = 42
    R43 = 43
    S44 = 44
    T45 = 45
    U46 = 46
    V47 = 47
    W48 = 48
    X49 = 49
    Y50 = 50
    Z51 = 51
    A52 = 52
    B53 = 53
    C54 = 54
    D55 = 55
    E56 = 56
    F57 = 57
    G58 = 58
    H59 = 59
    I60 = 60
    J61 = 61
    K62 = 62
    L63 = 63
    M64 = 64
    N65 = 65
    O66 = 66
    P67 = 67
    Q68 = 68
    R69 = 69
    S70 = 70
    T71 = 71
    U72 = 72
    V73 = 73
    W74 = 74
    X75 = 75
    Y76 = 76
    Z77 = 77
    A78 = 78
    B79 = 79
    C80 = 80
    D81 = 81
    E82 = 82
    F83 = 83
    G84 = 84
    H85 = 85
    I86 = 86
    J87 = 87
    K88 = 88
    L89 = 89
    M90 = 90
    N91 = 91
    O92 = 92
    P93 = 93
    Q94 = 94
    R95 = 95
    S96 = 96
    T97 = 97
    U98 = 98
    V99 = 99
    W100 = 100
    X101 = 101
    Y102 = 102
    Z103 = 103
    A104 = 104
    B105 = 105
    C106 = 106
    D107 = 107
    E108 = 108
    F109 = 109
    G110 = 110
    H111 = 111
    I112 = 112
    J113 = 113
    K114 = 114
    L115 = 115
    M116 = 116
    N117 = 117
    O118 = 118
    P119 = 119
    Q120 = 120
    R121 = 121
    S122 = 122
    T123 = 123
    U124 = 124
    V125 = 0x11111111
    W126 = 0x22222222
    X127 = 0xdeadbeef

proc quitOrDebug() {.noreturn, importc: "abort", header: "<stdlib.h>", nodecl.}

#proc `==`(a, b: Foo): bool {.borrow.}

proc fuzzMe(s: string, a, b, c: Foo) =
  if a == X127 and b == V125 and c == W126:
    if s.len == 100: echo "PANIC!"; quitOrDebug()

template `+!`(p: pointer, s: int): untyped =
  cast[pointer](cast[ByteAddress](p) +% s)

template inc(p: pointer, s: int) =
  p = cast[typeof(p)](cast[ByteAddress](p) +% s)

proc testOneInput(data: ptr UncheckedArray[byte], len: int): cint {.
    exportc: "LLVMFuzzerTestOneInput", raises: [].} =
  result = 0
  var data = data
  if len < sizeof(Foo) * 3 + 100: return
  let s = newString(100)
  copyMem(cstring(s), cast[cstring](data), s.len)
  var a, b, c: Foo
  inc data, 100
  copyMem(addr a, data, sizeof(a))
  inc data, sizeof(a)
  copyMem(addr b, data, sizeof(b))
  inc data, sizeof(b)
  copyMem(addr c, data, sizeof(c))
  fuzzMe(s, a, b, c)

when defined(fuzzSa):
  include standalone
else:
  proc initialize(): cint {.exportc: "LLVMFuzzerInitialize".} =
    {.emit: "N_CDECL(void, NimMain)(void); NimMain();".}

  proc mutate*(data: ptr UncheckedArray[byte], len, maxLen: int): int {.
      importc: "LLVMFuzzerMutate".}

  proc customMutator*(data: ptr UncheckedArray[byte], len, maxLen: int, seed: int64): int {.
      exportc: "LLVMFuzzerCustomMutator".} =
    var data1 = data
    var gen = initRand(seed)
    let s = newString(100)
    var a, b, c: Foo
    if len >= sizeof(Foo) * 3 + 100:
      copyMem(cstring(s), cast[cstring](data1), s.len)
      inc data1, 100
      copyMem(addr a, data1, sizeof(a))
      inc data1, sizeof(a)
      copyMem(addr b, data1, sizeof(b))
      inc data1, sizeof(b)
      copyMem(addr c, data1, sizeof(c))

    var size = 0
    size = mutate(cast[ptr UncheckedArray[byte]](cstring(s)), 100, 100)
    zeroMem(cstring(s) +! size, 100 - size)
    size = mutate(cast[ptr UncheckedArray[byte]](addr a), sizeof(a), sizeof(a))
    #zeroMem(addr(a) +! size, sizeof(a) - size)
    size = mutate(cast[ptr UncheckedArray[byte]](addr b), sizeof(b), sizeof(b))
    #zeroMem(addr(b) +! size, sizeof(b) - size)
    size = mutate(cast[ptr UncheckedArray[byte]](addr c), sizeof(c), sizeof(c))
    #zeroMem(addr(c) +! size, sizeof(c) - size)
    echo "VALUES a: ", a, ", b: ", b, ", c: ", c

    var data2 = data
    copyMem(cast[cstring](data2), cstring(s), s.len)
    inc data2, 100
    copyMem(data2, addr a, sizeof(a))
    inc data2, sizeof(a)
    copyMem(data2, addr b, sizeof(b))
    inc data2, sizeof(b)
    copyMem(data2, addr c, sizeof(c))
    result = sizeof(Foo) * 3 + 100
