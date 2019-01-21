withCredentials([
    string(
        credentialsId: "SECRET_TEXT_EXEMPLE", 
        variable: "SECRET_TEXT"
    ),
    usernamePassword(
        credentialsId: "SECRET_USERNAME_PASSWORD_EXEMPLE", 
        usernameVariable: 'SECRET_USERNAME', 
        passwordVariable: 'SECRET_PASSWORD'
    ),
    file(
        credentialsId: "SECRET_FILE_EXEMPLE", 
        variable: "SECRET_FILE"
    ),
    sshUserPrivateKey(
        credentialsId: 'SECRET_SSH_EXAMPLE', 
        keyFileVariable: 'SECRET_SSH_KEY', 
        passphraseVariable: 'SECRET_SSH_PASSPHRASE', 
        usernameVariable: 'SECRET_SSH_USERNAME'
    )
]){

    println "SECRET_TEXT: ${env.SECRET_TEXT}"
    println "SECRET_USERNAME: ${env.SECRET_USERNAME}"
    println "SECRET_PASSWORD: ${env.SECRET_PASSWORD}"

    println "SECRET_FILE"
    println sh "cat ${env.SECRET_FILE}"

    println "SECRET_SSH_KEY: ${env.SECRET_SSH_KEY}"
    println "SECRET_SSH_PASSPHRASE: ${env.SECRET_SSH_PASSPHRASE}"
    println "SECRET_SSH_USERNAME: ${env.SECRET_SSH_USERNAME}"

}

