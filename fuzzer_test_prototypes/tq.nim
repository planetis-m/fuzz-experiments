type
  SQLQueries = object
    queries: seq[CreateTable]

  CreateTable = object
    temp_table: Option[TempModifier]
    table: Table
    col_def: ColumnDef
    extra_col_defs: seq[ColumnDef]
    table_constraints: seq[TableConstraint]
    without_rowid: bool

proc toString(ct: CreateTable): string =
  result = "CREATE TABLE "
  if ct.temp_table.isSome():
    result.add toString(ct.temp_table.get())
    result.add " "
  result.add toString(ct.table)
  result.add "("
  result.add toString(ct.col_def)
  for i in 0 ..< ct.extra_col_defs.len:
    result.add ", "
    result.add toString(ct.extra_col_defs[i])
  for i in 0 ..< ct.table_constraints.len:
    result.add ", "
    result.add toString(ct.table_constraints[i])
  result.add ") "
  if ct.without_rowid:
    result.add "WITHOUT ROWID "

proc toString(queries: SQLQueries): string =
  result = ""
  for i in 0 ..< queries.len:
    result.add toString(queries.queries[i])
    result.add ";\n"

proc testOneInput(sql_queries: SQLQueries) =
  let queries = toString(sql_queries)
  runSQLQueries(queries) # Helper that passes our queries to sqlite library to execute
