#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# cleanup-vpc-dependencies.sh
# Run this if "terraform destroy" fails with:
#   DependencyViolation: The vpc 'vpc-xxx' has dependencies and cannot be deleted.
#
# Usage:
#   ./scripts/cleanup-vpc-dependencies.sh <vpc-id>
#   VPC_ID=vpc-xxx ./scripts/cleanup-vpc-dependencies.sh
#
# Requires: AWS CLI, jq (optional but recommended)
# Region: uses AWS_DEFAULT_REGION or add --region to aws commands.
# -----------------------------------------------------------------------------
set -euo pipefail

VPC_ID="${1:-${VPC_ID:-}}"
if [[ -z "$VPC_ID" ]]; then
  echo "Usage: $0 <vpc-id>" >&2
  echo "   or: VPC_ID=vpc-xxx $0" >&2
  exit 1
fi

REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
echo "VPC: $VPC_ID (region: $REGION)"

# --- 1. Delete Application Load Balancers in this VPC ---
SUBNETS=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$VPC_ID" --query 'Subnets[].SubnetId' --output text --region "$REGION" 2>/dev/null || true)
if [[ -n "$SUBNETS" ]]; then
  for ALB_ARN in $(aws elbv2 describe-load-balancers --region "$REGION" --query "LoadBalancers[?VpcId=='$VPC_ID'].LoadBalancerArn" --output text 2>/dev/null); do
    [[ -z "$ALB_ARN" ]] && continue
    echo "Deleting ALB: $ALB_ARN"
    aws elbv2 delete-load-balancer --load-balancer-arn "$ALB_ARN" --region "$REGION" || true
  done
fi

# --- 2. Delete Network Load Balancers in this VPC ---
for NLB_ARN in $(aws elbv2 describe-load-balancers --region "$REGION" --query "LoadBalancers[?VpcId=='$VPC_ID' && Type=='network'].LoadBalancerArn" --output text 2>/dev/null); do
  [[ -z "$NLB_ARN" ]] && continue
  echo "Deleting NLB: $NLB_ARN"
  aws elbv2 delete-load-balancer --load-balancer-arn "$NLB_ARN" --region "$REGION" || true
done

# --- 3. Classic ELBs in this VPC ---
for ELB_NAME in $(aws elb describe-load-balancers --region "$REGION" --query "LoadBalancerDescriptions[?VPCId=='$VPC_ID'].LoadBalancerName" --output text 2>/dev/null); do
  [[ -z "$ELB_NAME" ]] && continue
  echo "Deleting classic ELB: $ELB_NAME"
  aws elb delete-load-balancer --load-balancer-name "$ELB_NAME" --region "$REGION" || true
done

# --- 4. NAT Gateways in this VPC (release EIPs after) ---
for NATGW in $(aws ec2 describe-nat-gateways --filter "Name=vpc-id,Values=$VPC_ID" "Name=state,Values=available,pending" --query 'NatGateways[].NatGatewayId' --output text --region "$REGION" 2>/dev/null); do
  [[ -z "$NATGW" ]] && continue
  echo "Deleting NAT Gateway: $NATGW"
  aws ec2 delete-nat-gateway --nat-gateway-id "$NATGW" --region "$REGION" || true
done

echo "Waiting 30s for ENIs from load balancers/NAT to detach..."
sleep 30

# --- 5. Delete any VPC endpoints in this VPC ---
for EP in $(aws ec2 describe-vpc-endpoints --filters "Name=vpc-id,Values=$VPC_ID" --query 'VpcEndpoints[].VpcEndpointId' --output text --region "$REGION" 2>/dev/null); do
  [[ -z "$EP" ]] && continue
  echo "Deleting VPC endpoint: $EP"
  aws ec2 delete-vpc-endpoints --vpc-endpoint-ids "$EP" --region "$REGION" || true
done

echo "Cleanup done. Run: terraform destroy"
echo "If destroy still fails (e.g. ENIs from EKS), wait 5–10 minutes and run terraform destroy again."
