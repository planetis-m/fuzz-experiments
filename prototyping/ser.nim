type
  Unstructured = object
    data: ptr UncheckedArray[byte]
    pos, len: int

  Seq[T; maxLen: static[int]] = distinct seq[T]

  MemRange = object
    startAddr: ptr UncheckedArray[byte]
    len: int

  Navigator[T] = object
    m: MemRange

proc toUnstructured*(data: openarray[int8 | uint8]): Unstructured =
  Unstructured(data: cast[ptr UncheckedArray[byte]](data), pos: 0, len: data.len)

proc main =
  let u = toUnstructured([0xff'u8, 0x80, 0x00, 0x00])


main()
