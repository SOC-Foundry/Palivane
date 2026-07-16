output "gsa_email" {
  value = google_service_account.app.email
}
output "sql_connection_name" {
  value = google_sql_database_instance.this.connection_name
}
output "sql_instance" {
  value = google_sql_database_instance.this.name
}
