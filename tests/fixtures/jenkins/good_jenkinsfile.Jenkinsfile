// A hardened Declarative Jenkinsfile — same shape as the bad fixture
// but free of v0.4 starter-rule violations.
pipeline {
    // Constrained agent — pinned to a labelled node pool
    agent { label 'build-trusted' }

    environment {
        // All secret-shaped values come from the Credentials Provider
        API_TOKEN    = credentials('example-api-token')
        DB_PASSWORD  = credentials('example-db-password')
        GITHUB_TOKEN = credentials('github-pat')
        // Non-secret literals are fine
        BUILD_ENV = 'production'
    }

    stages {
        stage('Build') {
            // Image pinned to a SHA digest
            agent {
                docker {
                    image 'maven@sha256:9b3a72f8b8a5c5b4f4f6b3c1a2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3'
                }
            }
            steps {
                // No curl|bash, no eval $… — script is committed in-tree
                sh 'mvn -B -DskipTests clean package'
            }
        }

        stage('Deploy') {
            agent {
                docker {
                    image 'alpine:3.19@sha256:c5b1261d6d3e43071626931fc004f70149baeba2c8ec672bd4f27761f8e1ad6b'
                }
            }
            steps {
                sh 'kubectl apply -f deploy.yaml'
            }
        }
    }
}
