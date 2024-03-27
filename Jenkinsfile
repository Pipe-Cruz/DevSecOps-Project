pipeline {
    agent any
    
    tools {
        jdk 'jdk17'
        nodejs 'node16'
    }

    environment {
        SCANNER_HOME= tool 'sonar-scanner'
        EC2_URL = 'http://34.192.57.54'
    }

    stages {
        
        stage('Clean Workspace') {
            steps{
                script{
                    cleanWs()
                }      
            }
        }

        stage('Git Checkout') {
            steps {
                git branch: 'devsecops-project', url: 'https://github.com/Pipe-Cruz/DevSecOps-Project.git' 
            }
        }
        
        //SECRET SCANNING
        stage('GitLeaks Scan') {
            steps {
                script {
                    sh "docker rm -f gitleaks || true"
                    sh 'docker run -v \${WORKSPACE}:/path --name gitleaks ghcr.io/gitleaks/gitleaks:latest -s="/path" -f=json > gitleaks-report.json'
                }
            }
        }
        
        //SAST
        stage('SonarQube Scan') {
            steps {
                script {
                    withSonarQubeEnv('sonar-server') {
                    sh "$SCANNER_HOME/bin/sonar-scanner -Dsonar.projectKey=DevSecOps-project -Dsonar.projectName=DevSecOps-project"
                    }
                    /*
                    withCredentials([usernamePassword(credentialsId: 'sonarqubeAPI', usernameVariable: 'SONARQUBE_USERNAME', passwordVariable: 'SONARQUBE_PASSWORD')]) {
                        def vulnerabilities = sh(script: """
                            curl -s -u \$SONARQUBE_USERNAME:\$SONARQUBE_PASSWORD -X GET \
                            "http://54.145.218.228:9000/api/issues/search?id=Final-lab&severities=MAJOR,CRITICAL,BLOCKER" \
                            | jq -r '.total'
                        """, returnStdout: true).trim()
                        echo vulnerabilities
                        if (vulnerabilities.toInteger() > 0) {
                            error "SAST: Pipeline failure due to Major, Critical or Blocked category vulnerabilities in SonarQube."
                        } else {
                            echo "Quality Gate passed."
                        }
                    }
                    */
                }
            }
        }
        
        stage('Install Dependencies') {
            steps {
                sh "npm install"
            }
        }

        //SCA
        
        stage('Dependency-Check Scan') {
            steps {
                script {
                    withCredentials([string(credentialsId: 'DP-Check-token', variable: 'apiKeyDP')]) {
                        dependencyCheck additionalArguments: '--scan ./ --disableYarnAudit --disableNodeAudit --nvdApiKey=\${apiKeyDP}', odcInstallation: 'DP-Check'
                        dependencyCheckPublisher pattern: 'dependency-check-report.xml'
                        
                        /*
                        def vulnerabilitiesXml = readFile('/var/lib/jenkins/workspace/devsecops-project/dependency-check-report.xml')
                        def criticalVulnerabilities = vulnerabilitiesXml.contains('<severity>CRITICAL</severity>') ? 1 : 0
                        def highVulnerabilities = vulnerabilitiesXml.contains('<severity>HIGH</severity>') ? 1 : 0
                        def mediumVulnerabilities = vulnerabilitiesXml.contains('<severity>MEDIUM</severity>') ? 1 : 0

                        if (criticalVulnerabilities >  0 || highVulnerabilities > 0 || mediumVulnerabilities > 0) {
                            error "SCA: Pipeline failure due to medium, high, or critical category vulnerabilities in Dependency-Check."
                        } else {
                            echo "Dependency-Check passed."
                        }
                        */                 
                    }                  
                }
            }
        }
        

        stage('Trivy FileSystem Scan') {
            steps {
                sh 'trivy fs -f json -o trivy-filesystem-report.json .'  
            }
        }
        
        stage('Build & Tag Docker Image') {
            steps {
                script {
                    withDockerRegistry(credentialsId: 'dockerAPI', toolName: 'docker') {
                        withCredentials([string(credentialsId: 'TMDB_API_KEY_CREDENTIAL_ID', variable: 'TMDB_V3_API_KEY')]) {
                            sh "docker build --build-arg TMDB_V3_API_KEY=\${TMDB_V3_API_KEY} -t netflix ."
                            sh "docker tag netflix pipe7cruz/netflix:latest "
                        }
                    }
                }
            }
        }
        
        //IMAGE SECURITY
        stage('Trivy Image Scan') {
            steps {
                script {
                    sh "trivy image -f json -o trivy-image-report.json pipe7cruz/netflix:latest"
                    /*
                    def trivyReportJson = readFile(file: 'trivy-image-report.json')
                    def trivyReport = new groovy.json.JsonSlurper().parseText(trivyReportJson)
                    def severities = trivyReport.Results.Vulnerabilities.collect { it.Severity }.flatten()
                    if (severities.contains('CRITICAL') || severities.contains('HIGH') || severities.contains('MEDIUM')) {
                        error "Image Security: Pipeline failure due to medium, high, or critical category vulnerabilities in Trivy Image scan."
                    } else {
                        echo "Trivy Image Passed."
                    }
                    */
                }
            }
        }
        
        stage('Push Docker Image') {
            steps {
                script {
                    withDockerRegistry(credentialsId: 'dockerAPI', toolName:'docker'){              
                        sh "docker push pipe7cruz/netflix:latest"
                    }
                }
            }
        }
        
        stage('Deploy to container') {
            steps {
                script {
                    sh "docker rm -f netflix || true"
                    sh "docker run -d --name netflix -p 8081:80 pipe7cruz/netflix:latest"
                    sleep 30
                }
            }
        }
        
        /*
        stage('Deploy to Minikube') {
            steps {
                script {
                    sh 'minikube start'
                    sh 'sleep 30'
                    sh 'kubectl create deployment netflix --image=pipe7cruz/netflix:latest'
                    sh 'kubectl expose deployment netflix --type=NodePort --port=8081'
                    def serviceURL = sh(script: 'minikube service netflix --url', returnStdout: true).trim()
                    echo "Netflix application is accessible at: \${serviceURL}"
                }
            }
        }
        */
        //DAST
        stage('OWASP ZAP Scan') {
            steps {
                script {
                    sh "docker pull owasp/zap2docker-stable:latest"
                    sh "docker rm -f owasp || true"
                    sh "docker run -dt --name owasp owasp/zap2docker-stable /bin/bash"
                    sh "docker exec owasp mkdir /zap/wrk"
                    sh "docker exec owasp zap-baseline.py -t \${EC2_URL}:8081 -r owasp-zap-report.html -I"
                    sh "docker cp owasp:/zap/wrk/owasp-zap-report.html \${WORKSPACE}/owasp-zap-report.html"
                    sh "docker rm -f owasp"
                }
            }
        }
        
    }
    
    post {
        success {            
            archiveArtifacts 'gitleaks-report.json'
            archiveArtifacts 'dependency-check-report.xml'
            archiveArtifacts 'trivy-filesystem-report.json'
            archiveArtifacts 'trivy-image-report.json'
            archiveArtifacts 'owasp-zap-report.html'
        }

        always {
            emailext attachLog:true,
                subject: "SUCCESS JENKINS",
                body: "Project: \${env.JOB_NAME}<br/>" + "url: \${ENV.build_url}<br/>",
                to: 'felipecruz.cvg2000@gmail.com',
                attachmentsPattern: 'gitleaks-report.json'
        }
    } 
}