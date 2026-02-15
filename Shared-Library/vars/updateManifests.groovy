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
            sh "sed -i 's|image:.*|          image: ${imageUrl}|' deployment.yaml"
        }
    }

    echo "Update manifests stage completed"
}
