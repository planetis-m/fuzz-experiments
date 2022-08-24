import mutator

type
  OtherColor = enum
    Cyan, Magenta=2, Yellow=4, Black=8

#func fuzzTarget(x: set[OtherColor]) =
  #doAssert x != {Yellow}

func fuzzTarget(x: set[char]) =
  doAssert x != {'a'..'z'}

defaultMutator(fuzzTarget)
