#!/usr/bin/env groovy

/**
 * Shared Library Function: ScanImage
 * Scans Docker image for vulnerabilities using Trivy
 * 
 * @param imageName Full image name with tag (e.g., username/repo:tag)
 */
def call(String imageName) {
    echo "============================================"
    echo "Stage: ScanImage"
    echo "============================================"
    
    script {
        // Check if Trivy is installed, if not, install it
        def trivyPath = sh(
            script: 'which trivy || echo "not found"',
            returnStdout: true
        ).trim()
        
        if (trivyPath == 'not found') {
            echo "Trivy not found, installing..."
            def installDir = sh(
                script: '''
                    # Determine install directory (user-writable)
                    if [ -w ~/bin ] 2>/dev/null || mkdir -p ~/bin 2>/dev/null; then
                        echo ~/bin
                    elif [ -n "${WORKSPACE}" ] && mkdir -p ${WORKSPACE}/bin 2>/dev/null; then
                        echo ${WORKSPACE}/bin
                    else
                        echo /tmp
                    fi
                ''',
                returnStdout: true
            ).trim()
            
            sh """
                # Try apt method first (requires sudo), fallback to direct download
                if command -v apt-key >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
                    sudo wget -qO- https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add - && \
                    echo "deb https://aquasecurity.github.io/trivy-repo/deb \$(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list && \
                    sudo apt-get update && \
                    sudo apt-get install -y trivy || echo "apt installation failed, trying direct download..."
                fi
                # Direct download method (works without sudo)
                if ! command -v trivy >/dev/null 2>&1; then
                    echo "Installing Trivy via direct download to ${installDir}..."
                    # Pinned version (no curl/sed parsing – works on all Jenkins nodes)
                    TRIVY_TAG=v0.52.4
                    TRIVY_VERSION=0.52.4
                    wget -q "https://github.com/aquasecurity/trivy/releases/download/\${TRIVY_TAG}/trivy_\${TRIVY_VERSION}_Linux-64bit.tar.gz" -O trivy.tar.gz
                    tar -xzf trivy.tar.gz
                    mkdir -p ${installDir}
                    mv trivy ${installDir}/trivy
                    chmod +x ${installDir}/trivy
                    rm -f trivy.tar.gz
                    echo "Trivy installed to ${installDir}/trivy"
                fi
            """
            // Update PATH for subsequent commands
            env.PATH = "${installDir}:${env.PATH}"
        }
        
        // Scan the image (use full path if needed)
        echo "Scanning image: ${imageName}"
        try {
            sh """
                export PATH=${env.PATH}
                trivy image --exit-code 0 --severity HIGH,CRITICAL ${imageName} || echo "Scan completed with findings"
            """
        } catch (Exception e) {
            echo "Image scan completed with warnings. Continuing pipeline..."
            // Don't fail the pipeline on scan warnings
        }
    }
    
    echo "Scan image stage completed"
}
