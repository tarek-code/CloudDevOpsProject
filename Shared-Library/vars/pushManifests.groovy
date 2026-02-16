#!/usr/bin/env groovy

/**
 * Shared Library Function: PushManifests
 * Commits updated k8s manifests and pushes to the Git repository.
 *
 * @param commitMessage  Commit message (optional)
 * @param manifestsDir   Directory to add (default: k8s)
 * @param branch         Branch to push to (default: current branch or main)
 * @param credentialId   Jenkins credential ID for Git (username/password, e.g. github-credentials). Optional.
 * @param repoUrl        Full Git repo URL for push (e.g. https://github.com/org/repo.git). Required when credentialId is set.
 */
def call(String commitMessage = null, String manifestsDir = 'k8s', String branch = null, String credentialId = null, String repoUrl = null) {
    echo "============================================"
    echo "Stage: PushManifests"
    echo "============================================"

    script {
        def msg = commitMessage ?: "CI: update manifests for build ${env.BUILD_NUMBER}"
        def targetBranch = branch ?: (env.BRANCH_NAME ?: 'main')

        def doPush = {
            sh """
                git config user.email 'jenkins@localhost' || true
                git config user.name 'Jenkins' || true
                git add ${manifestsDir}/
                git diff --staged --quiet && echo 'No changes to commit' || git commit -m '${msg}'
            """
            if (credentialId?.trim() && repoUrl?.trim()) {
                def repoHostPath = repoUrl.replaceFirst('^https?://', '')
                withCredentials([usernamePassword(credentialsId: credentialId, usernameVariable: 'GIT_USER', passwordVariable: 'GIT_PASS')]) {
                    sh """
                        # GitHub PATs work in URLs, but ensure token is valid and has 'repo' scope
                        git remote set-url origin "https://\$GIT_USER:\$GIT_PASS@${repoHostPath}"
                        git push origin HEAD:${targetBranch} || true
                    """
                }
            } else {
                sh "git push origin HEAD:${targetBranch} || true"
            }
        }
        doPush()
    }

    echo "Push manifests stage completed"
}
