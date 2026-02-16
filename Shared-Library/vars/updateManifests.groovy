#!/usr/bin/env groovy

/**
 * Shared Library Function: UpdateManifests
 * Replaces the image in k8s deployment.yaml with the built image URL.
 *
 * @param imageUrl    Full image URL with tag (e.g. 123456789.dkr.ecr.us-east-1.amazonaws.com/ivolve-app:42)
 * @param manifestsDir Directory containing deployment.yaml (default: k8s)
 */
def call(String imageUrl, String manifestsDir = 'k8s') {
    echo "============================================"
    echo "Stage: UpdateManifests"
    echo "============================================"

    dir(manifestsDir) {
        script {
            if (!fileExists('deployment.yaml')) {
                error("deployment.yaml not found in ${manifestsDir}")
            }
            echo "Updating image to: ${imageUrl}"
            // Use a more precise sed pattern that preserves YAML structure
            // Match the image line with proper indentation (10 spaces) and replace only the value after the colon
            sh """
                sed -i 's|^\\(          image: \\).*|\\1${imageUrl}|' deployment.yaml
                # Verify YAML is still valid (basic check)
                python3 -c "import yaml; yaml.safe_load(open('deployment.yaml'))" 2>/dev/null || echo "Warning: YAML validation failed"
            """
        }
    }

    echo "Update manifests stage completed"
}
