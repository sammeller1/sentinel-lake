# ---------------------------------------------------------
# Sentinel Lake - Phase 2d: Athena analytics over processed logs
# ---------------------------------------------------------

resource "aws_glue_catalog_database" "sentinel" {
  name = "sentinel_lake"
}

resource "aws_glue_catalog_table" "events" {
  name          = "events"
  database_name = aws_glue_catalog_database.sentinel.name
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    classification       = "json"
    "projection.enabled" = "false"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.processed.id}/normalized/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"
    }

    columns {
      name = "class_name"
      type = "string"
    }
    columns {
      name = "class_uid"
      type = "int"
    }
    columns {
      name = "activity"
      type = "string"
    }
    columns {
      name = "time"
      type = "string"
    }
    columns {
      name = "status"
      type = "string"
    }
    columns {
      name = "status_id"
      type = "int"
    }
    columns {
      name = "severity"
      type = "string"
    }
    columns {
      name = "src_endpoint"
      type = "struct<ip:string,port:int>"
    }
    columns {
      name = "dst_endpoint"
      type = "struct<ip:string,port:int,hostname:string>"
    }
    columns {
      name = "actor"
      type = "struct<user:struct<name:string>>"
    }
    columns {
      name = "connection_info"
      type = "struct<protocol:string>"
    }
    columns {
      name = "metadata"
      type = "struct<product:string,log_source:string>"
    }
    columns {
      name = "raw_event"
      type = "string"
    }
  }
}

resource "aws_s3_bucket" "athena_results" {
  bucket = "sentinel-lake-athena-results-${random_id.suffix.hex}"
}

resource "aws_athena_workgroup" "sentinel" {
  name = "sentinel-lake"
  configuration {
    result_configuration {
      output_location = "s3://${aws_s3_bucket.athena_results.id}/results/"
    }
  }
}

output "athena_workgroup" {
  value = aws_athena_workgroup.sentinel.name
}

output "athena_database" {
  value = aws_glue_catalog_database.sentinel.name
}
