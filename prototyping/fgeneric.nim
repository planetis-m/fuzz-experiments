proc merge(dst: var bool; src: bool) = dst = src
proc merge(dst: var char; src: char) = dst = src
proc merge[T: SomeNumber](dst: T; src: T) = dst = src
proc merge[T: enum](dst: T; src: T) = dst = src
proc merge[T](dst: set[T]; src: T) = dst = src
proc merge(dst: string; src: T) = dst = src
proc merge[S, T](dst: var array[S, T]; src: array[S, T]) =
  for i in low(dst)..high(dst): dst[i] = src[i]
proc merge[T](dst: var seq[T], src: seq[T]) =
  setLen(dst, dst.len+src.len)
  for i in 0..high(dst): dst[dst.len+i] = src[i]
proc merge[T](dst: var ref T; src: ref T) = if src != nil: dst = src
proc merge[T](dst: var Option[T]; src: Option[T]) = if src.isSome: dst = src
proc merge[T: tuple](dst: var T; src: T) =
  for v1, v2 in fields(dst, src): merge(v1, v2)
proc merge[T: object](dst: var T; src: T) =
  for v1, v2 in fields(dst, src): merge(v1, v2)

