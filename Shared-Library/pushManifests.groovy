#!/usr/bin/env groovy

/**
 * Shared Library Function: PushManifests
 * Commits updated k8s manifests and pushes to the Git repository.
 *
 * @param commitMessage Commit message (optional)
 * @param manifestsDir  Directory to add (default: k8s)
 * @param branch        Branch to push to (default: current branch or main)
 */
def call(String commitMessage = null, String manifestsDir = 'k8s', String branch = null) {
    echo "============================================"
    echo "Stage: PushManifests"
    echo "============================================"

    script {
        def msg = commitMessage ?: "CI: update manifests for build ${env.BUILD_NUMBER}"
        def targetBranch = branch ?: (env.BRANCH_NAME ?: 'main')

        sh """
            git config user.email 'jenkins@localhost' || true
            git config user.name 'Jenkins' || true
            git add ${manifestsDir}/
            git diff --staged --quiet && echo 'No changes to commit' || git commit -m '${msg}'
            git push origin HEAD:${targetBranch} || true
        """
    }

    echo "Push manifests stage completed"
}
