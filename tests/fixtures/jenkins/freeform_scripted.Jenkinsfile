// A genuinely free-form Scripted Pipeline — `def` assignment and an `if`
// branch wrapping the node call. Should set is_scripted=True /
// style="scripted-unparseable" and produce zero findings (the CLI emits
// the "ciguard cannot model arbitrary Groovy" warning).
def deployTarget = env.BRANCH_NAME == 'main' ? 'prod' : 'staging'

if (deployTarget == 'prod') {
    node('prod-builder') {
        stage('Build') {
            sh 'make release'
        }
    }
} else {
    node('staging-builder') {
        stage('Build') {
            sh 'make snapshot'
        }
    }
}
