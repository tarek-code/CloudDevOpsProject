#!/usr/bin/env groovy

/**
 * Shared Library Function: BuildImage
 * Builds Docker image from Dockerfile
 *
 * @param imageName     Full image name with tag (e.g., repo:tag)
 * @param workDir       Working directory (build context). Default: .
 * @param dockerfilePath Optional path to Dockerfile from workDir (e.g. docker/Dockerfile). If unset, uses Dockerfile in workDir.
 */
def call(String imageName, String workDir = '.', String dockerfilePath = null) {
    echo "============================================"
    echo "Stage: BuildImage"
    echo "============================================"

    dir(workDir) {
        script {
            def dockerfile = dockerfilePath ?: 'Dockerfile'
            if (!fileExists(dockerfile)) {
                error("Dockerfile not found: ${workDir}/${dockerfile}")
            }
            echo "Building Docker image: ${imageName}"
            def buildCmd = dockerfilePath
                ? "docker build -f ${dockerfilePath} -t ${imageName} ."
                : "docker build -t ${imageName} ."
            sh """
                ${buildCmd}
                docker tag ${imageName} ${imageName.split(':')[0]}:latest
            """
        }
    }

    echo "Build image stage completed"
}
