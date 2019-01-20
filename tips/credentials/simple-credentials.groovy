import jenkins.model.Jenkins;
import com.cloudbees.plugins.credentials.*
import com.cloudbees.plugins.credentials.common.*
import com.cloudbees.plugins.credentials.domains.*
import com.cloudbees.plugins.credentials.impl.*
import com.cloudbees.jenkins.plugins.sshcredentials.impl.*
import org.jenkinsci.plugins.plaincredentials.*
import org.jenkinsci.plugins.plaincredentials.impl.*
import org.apache.commons.io.IOUtils;
import hudson.plugins.sshslaves.*
import hudson.util.Secret
import java.nio.file.Files
import java.nio.file.Paths
import java.nio.charset.StandardCharsets;


def credential_get_all_text_secret () {
    def _out = []
    def _cred = CredentialsProvider.lookupCredentials(
        Credentials.class,
        Jenkins.getInstance(),
        null,
        null
    )
    for (c in _cred) {
        if (c.getClass() == StringCredentialsImpl) {
            _out.push(c)
        }
    }
    return _out
}

def credential_get_text_secret (id){
    def creds = CredentialsProvider.lookupCredentials(
        Credentials.class,
        Jenkins.getInstance(),
        null,
        null
    )
    for (c in creds) {
        if (c.id.equalsIgnoreCase(id) && c.getClass() == StringCredentialsImpl) {
            return c
        }
    }
    return false
}

def credential_get_file_secret (id, targetPath) {
    def creds = CredentialsProvider.lookupCredentials(
        Credentials.class,
        Jenkins.getInstance(),
        null,
        null
    )
    for (c in creds) {
        if(c.id.equalsIgnoreCase(id) && c.getClass() == FileCredentialsImpl){
            new File("/tmp/${targetPath}").write(IOUtils.toString(c.getContent(), StandardCharsets.UTF_8))
            return c.id
        }
    }
    return false
}

def credential_add_text_secret (id, desc, text) {
    def store = Jenkins.getInstance().getExtensionList('com.cloudbees.plugins.credentials.SystemCredentialsProvider')[0].getStore()
    def secretText = new StringCredentialsImpl(
        CredentialsScope.GLOBAL,
        id,
        desc,
        Secret.fromString(text)
    )
    store.addCredentials(Domain.global(), secretText)
}

def credential_add_file_secret (id, desc, filename) {
    def store = Jenkins.getInstance().getExtensionList('com.cloudbees.plugins.credentials.SystemCredentialsProvider')[0].getStore()
    def path = Paths.get(filename)
    def secretBytes = SecretBytes.fromBytes(Files.readAllBytes(path))
    def secretFile = new FileCredentialsImpl(
        CredentialsScope.GLOBAL,
        id,
        desc,
        "${path.getFileName()}",
        secretBytes
    )
    store.addCredentials(Domain.global(), secretFile)
}

def credential_add_file_secret_by_content (id, desc, text, filename) {
    def store = Jenkins.getInstance().getExtensionList('com.cloudbees.plugins.credentials.SystemCredentialsProvider')[0].getStore()
    def uuid = UUID.randomUUID().toString()
    new File("/tmp/${uuid}").write(text)
    def secretBytes = SecretBytes.fromBytes(Files.readAllBytes(Paths.get("/tmp/${uuid}")))
    def secretFile = new FileCredentialsImpl(
        CredentialsScope.GLOBAL,
        id,
        desc,
        "${filename}",
        secretBytes
    )
    store.addCredentials(Domain.global(), secretFile)
    Files.delete(Paths.get("/tmp/${uuid}"))
}

def credential_add_ssh_secret (id, description, text, username, passphrase) {
    def store = Jenkins.getInstance().getExtensionList('com.cloudbees.plugins.credentials.SystemCredentialsProvider')[0].getStore()
    def creds = new BasicSSHUserPrivateKey(
        CredentialsScope.GLOBAL,
        id,
        username,
        new BasicSSHUserPrivateKey.DirectEntryPrivateKeySource(text),
        passphrase,
        description
    )
    store.addCredentials(Domain.global(), creds)
}

def credential_add_username_and_password (id, description, username, passphrase) {
    def store = Jenkins.getInstance().getExtensionList('com.cloudbees.plugins.credentials.SystemCredentialsProvider')[0].getStore()
    def creds = new UsernamePasswordCredentialsImpl(
        CredentialsScope.GLOBAL,
        id,
        description,
        username,
        passphrase
    )
    store.addCredentials(Domain.global(), creds)
}

def credential_exists (id) {
    def creds = CredentialsProvider.lookupCredentials(
        Credentials.class,
        Jenkins.getInstance(),
        null,
        null
    )
    for (c in creds) {
        if(c.id.equalsIgnoreCase(id)){
            return true
        }
    }
    return false
}

def credential_delete (id) {
    def store = Jenkins.getInstance().getExtensionList('com.cloudbees.plugins.credentials.SystemCredentialsProvider')[0].getStore()
    def creds = CredentialsProvider.lookupCredentials(
        Credentials.class,
        Jenkins.getInstance(),
        null,
        null
    )
    for (c in creds) {
        if(c.id.equalsIgnoreCase(id)){
            store.removeCredentials(Domain.global(), c)
            return true
        }
    }
    return false
}

def credential_crypty (string) {
    return Secret.fromString(string).getEncryptedValue()
}

def credential_decrypt (encrypted) {
    return Secret.fromString(encrypted).getPlainText()
}

/*Testando as funções*/
def test_credential_text_id = "TEXT_CREDENTIAL"
println "Adicionando text secret"
println credential_add_text_secret(test_credential_text_id, "Description of ${test_credential_text_id}", "123456")
println "Verificando se a credencial existe"
println credential_exists(test_credential_text_id)
println "Obtendo a credencial de texto"
def test_credential_text = credential_get_text_secret(test_credential_text_id)
println test_credential_text.getSecret()


def test_credential_ssh_id = "SSH_CREDENTIAL"
println "Adicionando ssh credential"
println credential_add_ssh_secret(test_credential_ssh_id, "Description of ${test_credential_ssh_id}", "CONTENT_OF_SSH_KEY", "username", "passphrase")


def test_credential_file_id = "FILE_CREDENTIAL"
println credential_add_file_secret(test_credential_file_id, "Description of ${test_credential_file_id}", "/etc/hosts")
println credential_add_file_secret_by_content("${test_credential_file_id}_CONTENT", "Description of ${test_credential_file_id}", "conteudo do arquivo", "arquivo.txt")
println credential_get_file_secret(test_credential_file_id, 'file')


def test_credential_username_password_id = "USER_PASS_CREDENTIAL"
println credential_add_username_and_password(test_credential_username_password_id, "Description of ${test_credential_username_password_id}", "username", "passphrase")
println "Removendo credencial de usuário e senha"
println credential_delete(test_credential_username_password_id)

println "Obtendo todas as credenciais"
println credential_get_all_text_secret()

println "Removendo credencial de texto"
println credential_delete(test_credential_text_id)

println "Removendo credencial de ssh"
println credential_delete(test_credential_ssh_id)

println "Removendo credencial de arquivo"
println credential_delete(test_credential_file_id)
println credential_delete("${test_credential_file_id}_CONTENT")

println "Encriptando o valor"
println credential_crypty("123456")
println "Decriptando o valor"
println credential_decrypt(credential_crypty("123456"))

