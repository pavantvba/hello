pipeline{
	agent {
		docker 'node:6.3'
	}
	stages {
		stage ('build'){
			steps{
				sh 'echo "Hello World!"'
				sh 'npm --version'
			}
		}
	}

}
