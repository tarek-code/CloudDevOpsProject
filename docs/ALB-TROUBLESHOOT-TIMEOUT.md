# ALB "Can't be reached" / ERR_CONNECTION_TIMED_OUT

If you already added inbound HTTP 80 from 0.0.0.0/0 to the ALB security group(s) and still get a timeout:

- **Curl from inside VPC also times out** → Something is blocking traffic **to** the ALB (listener, security groups, or NACLs). See section "When curl from EC2 also times out" below.
- **Curl from inside VPC works** → ALB is in **private subnets** (no public IP). See section 2–3 below.

## When curl from EC2 (inside VPC) also times out

Then the ALB is not accepting connections at all. Check in **AWS Console** (no extra IAM needed):

1. **EC2 → Load balancers** → open **k8s-ivolve-ivolveap-7c0065a7da**
   - **Listeners** tab: there must be a **Listener** on **HTTP : 80** with action **Forward** to the correct target group. If it’s missing or wrong, the controller or Ingress may be misconfigured.
   - **Security** tab: note the security groups attached to the ALB.
2. **EC2 → Security groups** → for **each** SG attached to the ALB:
   - **Inbound rules** must include **HTTP, port 80, Source 0.0.0.0/0** (or at least the VPC CIDR / your EC2 CIDR for testing). If **any** attached SG has no rule allowing 80 from your source, and the others don’t either, traffic is denied. (AWS allows traffic if any one SG allows it.)
3. **VPC → Network ACLs**: open the NACL for the **subnets where the ALB lives** (see ALB **Network** subnets):
   - **Inbound**: allow **HTTP 80** from **0.0.0.0/0** (or 80 from your test CIDR).
   - **Outbound**: allow ephemeral ports (e.g. 1024–65535) to 0.0.0.0/0 so responses can return.

After fixing listener, SGs, or NACLs, try curl from EC2 again.

---

## 1. Check from inside the VPC (SSH to Jenkins EC2)

```bash
curl -v --connect-timeout 5 http://k8s-ivolve-ivolveap-7c0065a7da-2103442340.us-east-1.elb.amazonaws.com/
```

- **If you get HTTP 200** → ALB and targets work; the ALB is **not reachable from the internet** (almost always = ALB in **private** subnets).
- **If connection times out** → problem can be listener, SG from ALB to targets, or NACLs.

## 2. Check which subnets the ALB is in (must be PUBLIC)

Run on the EC2 host (or any machine with AWS CLI and same region):

```bash
REGION=us-east-1
ALB_DNS="k8s-ivolve-ivolveap-7c0065a7da-2103442340.us-east-1.elb.amazonaws.com"

# Get ALB ARN and subnet IDs
ALB_ARN=$(aws elbv2 describe-load-balancers --region $REGION --query "LoadBalancers[?DNSName=='$ALB_DNS'].LoadBalancerArn" --output text)
aws elbv2 describe-load-balancers --region $REGION --load-balancer-arns $ALB_ARN \
  --query 'LoadBalancers[0].AvailabilityZones[*].{Zone:ZoneName,SubnetId:SubnetId}' --output table
```

For **each SubnetId** from the output, check if that subnet has a route to an **Internet Gateway**:

```bash
# Replace SUBNET_ID with each subnet from above (e.g. subnet-0384895451477e827 subnet-05a6645183380e3c1)
REGION=us-east-1
for SUBNET_ID in subnet-0384895451477e827 subnet-05a6645183380e3c1; do
  echo -n "$SUBNET_ID: "
  aws ec2 describe-route-tables --region $REGION --filters "Name=association.subnet-id,Values=$SUBNET_ID" \
    --query 'RouteTables[].Routes[?GatewayId!=`local`].GatewayId' --output text | grep -q igw- && echo "PUBLIC (igw)" || echo "PRIVATE (no igw)"
done
```

- **`igw-xxxxx`** → that subnet is **public** (good).
- **`nat-xxxxx`** or nothing → that subnet is **private**. An ALB in only private subnets **cannot** be reached from the internet.

## 3. Fix: put the ALB in public subnets

The controller picks subnets by **tags**. For an **internet-facing** ALB it uses subnets tagged:

- **Key:** `kubernetes.io/role/elb`
- **Value:** `1`

Those subnets must be **public** (have a route to an IGW).

### In AWS Console

1. **VPC → Subnets** → find your **public** subnets (route table has 0.0.0.0/0 → igw-xxxxx).
2. For each **public** subnet: **Subnet** → **Tags** → add:
   - Key: `kubernetes.io/role/elb`
   - Value: `1`
3. Ensure **private** subnets do **not** have this tag (remove it if present).
4. **Recreate the ALB** so the controller uses the public subnets:
   ```bash
   kubectl delete ingress -n ivolve ivolve-app-ingress
   # Wait 2–3 minutes for ALB to be deleted
   kubectl apply -f k8s/ingress.yaml
   ```

### Or force subnets via Ingress (if you know public subnet IDs)

Add to your Ingress annotations (use your real public subnet IDs):

```yaml
alb.ingress.kubernetes.io/subnets: "subnet-pub1,subnet-pub2"
```

Then delete the Ingress and apply again.

## 4. Quick recap

| Symptom | Likely cause |
|--------|----------------|
| Timeout from browser, curl from EC2 works | ALB in **private** subnets → tag public subnets and recreate Ingress |
| Timeout from browser and from EC2 | Listener, SG (ALB→pods), or NACLs |
| 503 / no healthy targets | Target group health check or SG from ALB to pods (port 5000) |

After fixing subnets and recreating the Ingress, try the ALB URL again from your browser.
