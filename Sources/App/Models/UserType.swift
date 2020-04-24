import FluentPostgreSQL

enum UserType: String, PostgreSQLEnum, PostgreSQLMigration {
  case admin
  case standard
  case restricted
}
