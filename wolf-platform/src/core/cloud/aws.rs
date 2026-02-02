use super::{CloudProvider, CloudResource, CloudScanResult, SecurityFinding};
use async_trait::async_trait;
use anyhow::{Result, Context};
use std::collections::HashMap;
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_ec2::{Client as Ec2Client};
use aws_sdk_s3::{Client as S3Client};
use chrono::Utc;

pub struct AwsScanner {
    ec2_client: Ec2Client,
    s3_client: S3Client,
    region: String,
}

impl AwsScanner {
    pub async fn new() -> Result<Self> {
        let region_provider = RegionProviderChain::default_provider().or_else("us-east-1");
        let config = aws_config::from_env().region(region_provider).load().await;
        
        // Setup clients
        let ec2_client = Ec2Client::new(&config);
        let s3_client = S3Client::new(&config);
        
        let region = config.region().map(|r| r.to_string()).unwrap_or_else(|| "unknown".to_string());

        Ok(Self {
            ec2_client,
            s3_client,
            region,
        })
    }
}

#[async_trait]
impl CloudProvider for AwsScanner {
    async fn status(&self) -> Result<String> {
        // Simple check: describe regions or identity
        match self.ec2_client.describe_regions().send().await {
            Ok(_) => Ok("Connected".to_string()),
            Err(e) => Ok(format!("Error: {}", e)),
        }
    }

    async fn scan(&self) -> Result<CloudScanResult> {
        let mut resources = Vec::new();
        let mut findings = Vec::new();

        // 1. Scan EC2
        match self.ec2_client.describe_instances().send().await {
            Ok(result) => {
                for reservation in result.reservations.unwrap_or_else(|| Vec::new()) {
                    for instance in reservation.instances.unwrap_or_else(|| Vec::new()) {
                        let id = instance.instance_id.clone().unwrap_or_else(|| "unknown-id".to_string());
                        let state = instance.state.as_ref()
                            .and_then(|s| s.name.as_ref())
                            .map(|n| n.as_str().to_string())
                            .unwrap_or_else(|| "unknown".to_string());
                        
                        let public_ip = instance.public_ip_address.clone();
                        
                        let name = instance.tags.as_ref()
                            .and_then(|tags| tags.iter().find(|t| t.key == Some("Name".to_string())))
                            .and_then(|t| t.value.clone())
                            .unwrap_or_else(|| "Unnamed".to_string());

                        let is_public = public_ip.is_some();
                        
                        if is_public && state == "running" {
                            findings.push(SecurityFinding {
                                severity: "MEDIUM".to_string(),
                                title: "EC2 Instance with Public IP".to_string(),
                                description: format!("Instance {} ({}) has public IP {:?}", name, id, public_ip),
                                resource_id: id.clone(),
                            });
                        }

                        resources.push(CloudResource {
                            id,
                            name,
                            resource_type: "EC2".to_string(),
                            region: self.region.clone(),
                            status: state,
                            public_access: is_public,
                            tags: HashMap::new(),
                            details: format!("Type: {:?}, IP: {:?}", instance.instance_type, public_ip),
                        });
                    }
                }
            }
            Err(e) => findings.push(SecurityFinding {
                severity: "HIGH".to_string(),
                title: "Failed to scan EC2".to_string(),
                description: e.to_string(),
                resource_id: "AWS-EC2".to_string(),
            }),
        }

        // 2. Scan S3
        match self.s3_client.list_buckets().send().await {
            Ok(result) => {
                for bucket in result.buckets.unwrap_or_else(|| Vec::new()) {
                    let name = bucket.name.clone().unwrap_or_else(|| "unknown-bucket".to_string());
                    
                    // Basic finding: just listing them implies we have access
                    // Deep scan would check get_public_access_block
                    
                    resources.push(CloudResource {
                        id: name.clone(),
                        name: name.clone(),
                        resource_type: "S3".to_string(),
                        region: "global".to_string(), // S3 is global/regional mix
                        status: "Active".to_string(),
                        public_access: false, // Default assumption until checked
                        tags: HashMap::new(),
                        details: "Bucket found".to_string(),
                    });
                }
            }
            Err(e) => findings.push(SecurityFinding {
                severity: "HIGH".to_string(),
                title: "Failed to scan S3".to_string(),
                description: e.to_string(),
                resource_id: "AWS-S3".to_string(),
            }),
        }

        Ok(CloudScanResult {
            provider: "AWS".to_string(),
            resources,
            findings,
            timestamp: Utc::now().timestamp(),
        })
    }
}
