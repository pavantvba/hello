pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                echo 'Building'
                sh 'mvn -B -DskipTests clean package'
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
        stage('Sanity Check Test') {
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
        always {
            echo 'Deployment done on all stages..'
        }
    }
}
