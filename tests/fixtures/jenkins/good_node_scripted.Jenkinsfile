// A clean node-style Scripted Jenkinsfile — no JKN-* rules should fire.
// Pinned label, no dangerous shell patterns, no secret literals.
node('build-trusted') {
    stage('Build') {
        sh 'mvn -B -ntp clean package'
    }
    stage('Test') {
        sh 'mvn -B -ntp verify'
    }
    stage('Publish') {
        sh 'mvn -B -ntp deploy -DskipTests'
    }
}
