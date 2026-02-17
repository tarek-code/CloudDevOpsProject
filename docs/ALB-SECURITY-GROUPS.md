# Why the ALB "Shared Backend" security group has no inbound rules

## What the controller does

The [AWS Load Balancer Controller](https://kubernetes-sigs.github.io/aws-load-balancer-controller/latest/deploy/security_groups/) uses two kinds of security groups:

1. **Frontend (Managed) security group**  
   - One per ALB.  
   - The controller **adds inbound rules** here from `inbound-cidrs` (e.g. `0.0.0.0/0`) to `listen-ports` (e.g. 80).  
   - This is what allows clients from the internet to reach the ALB.

2. **Backend (Shared) security group**  
   - One shared SG for the cluster, attached to every ALB.  
   - Used so that **targets (pods)** can allow traffic **from the ALB**: the controller adds rules on the **pod** security groups like “allow inbound from this backend SG on port 5000”.  
   - The controller **does not add any inbound rules to this backend SG itself**.  
   - By design it is only an identity: “traffic from this SG = from the ALB”.

So: **the “code” (the controller) never adds inbound rules to the Shared Backend SG on purpose.**  
Client access is intended to be allowed only via the **Managed (frontend)** SG.

## Why you saw “no inbound” on the Shared Backend

- **Shared Backend SG** → no inbound rules from the controller (by design).  
- **Managed SG** → should have HTTP 80 from `0.0.0.0/0` from the controller (driven by `alb.ingress.kubernetes.io/inbound-cidrs` and `listen-ports`).

If the ALB was unreachable until you added an inbound rule on the Shared Backend SG, possible causes are:

- The Managed SG’s rule was missing or had the wrong source (e.g. not `0.0.0.0/0`), or  
- Only the Shared Backend SG was attached to the ALB in your setup.

Adding HTTP 80 from `0.0.0.0/0` on the Shared Backend SG is a valid workaround so the ALB accepts traffic, but it’s not how the controller is designed to work.

## Option: use only the Managed SG (single SG on the ALB)

To avoid having two SGs on the ALB and to rely only on the frontend SG for client access, you can disable the shared backend SG. The controller will then use the **Managed (frontend)** SG as the source when adding rules to the pod security groups.

In the Helm values for the controller (e.g. `ansible/roles/helm-install/files/alb-controller-fargate-values.yaml`), set:

```yaml
enableBackendSecurityGroup: false
```

Then reinstall/upgrade the controller and recreate the Ingress (delete + apply) so the ALB is recreated with only the Managed SG. The Managed SG should get the correct inbound rule from the controller (e.g. 80 from `0.0.0.0/0`) from your Ingress annotations.
