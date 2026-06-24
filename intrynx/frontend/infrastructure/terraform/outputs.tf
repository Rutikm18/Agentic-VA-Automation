output "cluster_name"        { value = module.eks.cluster_name }
output "cluster_endpoint"    { value = module.eks.cluster_endpoint; sensitive = true }
output "cluster_oidc_issuer" { value = module.eks.cluster_oidc_issuer_url }
output "rds_endpoint"        { value = aws_db_instance.adversa.endpoint; sensitive = true }
output "redis_endpoint"      { value = aws_elasticache_replication_group.adversa.primary_endpoint_address; sensitive = true }
output "kafka_brokers"       { value = aws_msk_cluster.adversa.bootstrap_brokers_tls; sensitive = true }
output "artifacts_bucket"    { value = aws_s3_bucket.artifacts.bucket }
output "api_iam_role_arn"    { value = aws_iam_role.adversa_api.arn }
