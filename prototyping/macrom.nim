import macros

template getFieldValue(tmpSym, srcSym, fieldSym) =
  merge(tmpSym.fieldSym, srcSym.fieldSym)

template getKindValue(tmpSym, kindSym, kindType) =
  var kindTmp: kindType
  kindTmp = mutate(kindTmp, sizeIncreaseHint, r)
  {.cast(uncheckedAssign).}:
    tmpSym.kindSym = kindTmp

proc foldObjectBody(typeNode, tmpSym, srcSym: NimNode): NimNode =
  case typeNode.kind
  of nnkEmpty:
    result = newNimNode(nnkNone)
  of nnkRecList:
    result = newStmtList()
    for it in typeNode:
      let x = foldObjectBody(it, tmpSym, stream)
      if x.kind != nnkNone: result.add x
  of nnkIdentDefs:
    expectLen(typeNode, 3)
    let fieldSym = typeNode[0]
    result = getAst(getFieldValue(tmpSym, srcSym, fieldSym))
  of nnkRecCase:
    let kindSym = typeNode[0][0]
    let kindType = typeNode[0][1]
    result = getAst(getKindValue(tmpSym, kindSym, kindType))
    let inner = nnkCaseStmt.newTree(nnkDotExpr.newTree(tmpSym, kindSym))
    for i in 1..<typeNode.len:
      let x = foldObjectBody(typeNode[i], tmpSym, stream)
      if x.kind != nnkNone: inner.add x
    result.add inner
  of nnkOfBranch, nnkElse:
    result = copyNimNode(typeNode)
    for i in 0..typeNode.len-2:
      result.add copyNimTree(typeNode[i])
    let inner = newNimNode(nnkStmtListExpr)
    let x = foldObjectBody(typeNode[^1], tmpSym, stream)
    if x.kind != nnkNone: inner.add x
    result.add inner
  of nnkObjectTy:
    expectKind(typeNode[0], nnkEmpty)
    expectKind(typeNode[1], {nnkEmpty, nnkOfInherit})
    result = newNimNode(nnkNone)
    if typeNode[1].kind == nnkOfInherit:
      let base = typeNode[1][0]
      var impl = getTypeImpl(base)
      while impl.kind in {nnkRefTy, nnkPtrTy}:
        impl = getTypeImpl(impl[0])
      result = foldObjectBody(impl, tmpSym, stream)
    let body = typeNode[2]
    let x = foldObjectBody(body, tmpSym, stream)
    if result.kind != nnkNone:
      if x.kind != nnkNone:
        for i in 0..<result.len: x.add(result[i])
        result = x
    else: result = x
  else:
    error("unhandled kind: " & $typeNode.kind, typeNode)

macro assignObjectImpl(dst, src: typed; call: untyped): untyped =
  let typeSym = getTypeInst(dst)
  result = newStmtList()
  let x = foldObjectBody(typeSym.getTypeImpl, dst, src, call)
  if x.kind != nnkNone: result.add x

proc merge[T: object](dst: var T; src: T) =
  assignObjectImpl(dst, src, ident"merge")
