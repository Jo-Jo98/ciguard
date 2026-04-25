// A canonical jenkinsci/* plugin Jenkinsfile — the entire pipeline body
// lives in the shared library, this file just delegates. Should fire
// JKN-LIB-001 (Info, coverage gap) and nothing else.
@Library('common-jenkinsci') _

buildPlugin(useContainerAgent: true,
            forkCount: '0.5C',
            timeout: 360,
            configurations: [
                [platform: 'linux',   jdk: 21],
                [platform: 'windows', jdk: 21],
            ])
