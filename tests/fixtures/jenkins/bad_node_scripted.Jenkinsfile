// Deliberately-vulnerable node-style Scripted Jenkinsfile used by
// ciguard v0.4.1 fixture tests. Each issue corresponds to an existing
// JKN-* rule that should now fire on Scripted pipelines too.

// Triggers JKN-RUN-001 — `node` with no label is the Scripted equivalent
// of `agent any`.
node {
    stage('Build') {
        // Triggers JKN-SC-001 — curl pipe to bash.
        sh 'curl -sSL https://get.example.com/install.sh | bash'
    }
    stage('Deploy') {
        // Triggers JKN-SC-001 — eval expanding an env var.
        sh '''
            set -eu
            echo "Deploying..."
            eval "$DEPLOY_CMD"
        '''
    }
}
