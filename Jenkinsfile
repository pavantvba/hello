pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                echo 'Building'
            }
        }
        stage('Sanity Check') {
            steps {
                input 'Does Build action sucessfull?'
            }
        }
        stage('Test') {
            steps {
                echo 'Testing'
            }
        }
        stage('Sanity Check') {
            steps {
                input 'Does Testing environment is ok?'
            }
        }
        stage('Deploy') {
            steps {
                echo 'Deploying'
            }
        }
    }
    post {
        allways {
            echo 'Deployment done on all stages..'
        }
    }
}
