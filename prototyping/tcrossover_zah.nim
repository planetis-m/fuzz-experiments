import
  sequtils, random,
  stew/shims/macros,
  stew/objects

type
  A = object
    s: string
    i: int
    b: B
    i2: int
    s2: ref string

  B = object
    f: float
    r: ref B
    s: string

macro crossoverImpl(
  assignments: untyped,
  isAssignmentPossible: static seq[bool]): untyped =

  echo isAssignmentPossible
  let possibleAssignmentsCount = count(isAssignmentPossible, true)

  if possibleAssignmentsCount > 0:
    var caseStmt = newTree(
      nnkCaseStmt,
      newTree(nnkCall, bindSym"rand", newLit(possibleAssignmentsCount)))

    var caseIdx = 0
    for i in 0 ..< assignments.len:
      if isAssignmentPossible[i]:
        let
          lhs = assignments[i][0]
          rhs = assignments[i][1]
          assignment = quote do:
            `lhs` = `rhs`

        caseStmt.add newTree(nnkOfBranch, newLit(caseIdx), assignment)
        inc caseIdx

    caseStmt.add newTree(nnkElse, newStmtList())
    echo caseStmt.repr
    return caseStmt
  else:
    return newStmtList()

macro crossover[T](a, b: T): untyped =
  var
    assignments = newTree(nnkBracket)
    isAssignmentPossible = newTree(nnkBracket)

  let Tresolved = getType(a)

  for lhsField in recordFields(Tresolved):
    for rhsField in recordFields(Tresolved):
      let
        lhs = newTree(nnkDotExpr, a, newIdentNode($lhsField.name))
        rhs = newTree(nnkDotExpr, b, newIdentNode($rhsField.name))
        lhsDereffed = newTree(nnkBracketExpr, lhs)

      isAssignmentPossible.add quote do:
        compiles:
          `lhs` = `rhs`

      assignments.add(newTree(nnkTupleConstr, lhs, rhs))

      isAssignmentPossible.add quote do:
        compiles:
          `lhsDereffed` = `rhs`

      assignments.add(newTree(nnkTupleConstr, lhsDereffed, rhs))

  result = newCall(bindSym"crossoverImpl",
                   assignments,
                   newTree(nnkPrefix, bindSym"@", isAssignmentPossible))

proc main =
  var a, b: A
  crossover(a, b)
