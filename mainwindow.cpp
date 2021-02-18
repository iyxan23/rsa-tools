#include "mainwindow.h"
#include "ui_mainwindow.h"

// Qt Libraries
#include <QtCore>
#include <QDesktopServices>
#include <QMessageBox>
#include <QFileDialog>
#include <QDir>

// OpenSSL Libraries
#include <openssl/crypto.h>
#include <openssl/rsa.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow) {
    ui->setupUi(this);

    // Init OpenSSL
    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings();

    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    /* Load config file, and other important initialisation */
    OPENSSL_config(NULL);
}

MainWindow::~MainWindow() {
    // Clean Up OpenSSL
    /* Removes all digests and ciphers */
    EVP_cleanup();

    /* if you omit the next, a small leak may be left when you make use of the BIO (low level API) for e.g. base64 transformations */
    CRYPTO_cleanup_all_ex_data();

    /* Remove error strings */
    ERR_free_strings();

    // Delete unused stuff
    delete ui;
}


// GitHub button
void MainWindow::on_pushButton_5_released() {
    if (!QDesktopServices::openUrl(QUrl("https://github.com/Iyxan23/rsa-tools"))) {
        QMessageBox box;
        box.setText("Failed to open link");
        box.exec();
    }
}

void MainWindow::on_openfile_public_key_clicked() {
    QString filepath = QFileDialog::getOpenFileName(this,
        tr("Open Public Key"), QDir::currentPath(), tr("PEM File (*.pem)"));

    QFile file(filepath);

    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QMessageBox box;
        box.setText("Failed to open file");
        box.exec();

        return;
    }

    QByteArray fileContents = file.readAll();

    ui->public_key_text->insertPlainText(fileContents);
}

void MainWindow::on_openfile_private_key_clicked() {
    QString filepath = QFileDialog::getOpenFileName(this,
        tr("Open Private Key"), QDir::currentPath(), tr("PEM File (*.pem)"));

    QFile file(filepath);

    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QMessageBox box;
        box.setText("Failed to open file");
        box.exec();

        return;
    }

    QByteArray fileContents = file.readAll();

    ui->private_key_text->insertPlainText(fileContents);
}

void MainWindow::on_public_key_text_textChanged() {
    // Note: yes, this can be simplified, but making it like this can increase the code readability

    if (ui->public_key_text->toPlainText().trimmed() == "") {
        // Empty, disable the button
        ui->encrypt_button->setEnabled(false);

        // The public key doesn't exists
        public_key_exists = false;
    } else {
        // Something is there, enable it
        ui->encrypt_button->setEnabled(true);

        // The public key exists!
        public_key_exists = true;
    }
}

void MainWindow::on_private_key_text_textChanged() {
    // Note: yes, this can be simplified, but making it like this can increase the code readability

    if (ui->private_key_text->toPlainText().trimmed() == "") {
        // Empty, disable the button
        ui->decrypt_button->setEnabled(false);

        // The private key doesn't exists
        private_key_exists = false;
    } else {
        // Something is there, enable it
        ui->decrypt_button->setEnabled(true);

        // The private key exists!
        private_key_exists = true;
    }
}

void MainWindow::on_encrypt_button_clicked() {
    // Encrypt the text!

    // Get the public key
    QByteArray public_key = ui->public_key_text->toPlainText().toUtf8();

    // Put it in a BIO
    BIO* bio = BIO_new_mem_buf(public_key, -1);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    // Then read the bio to get the public key

    /* Some Important notes to remember:
     * PEM_read_RSAPublicKey -> Read public key from a FILE in PKCS#1 Format, (in openssl command line, to generate that, use the `-outform DER` parameter)
     * PEM_read_RSA_PUBKEY -> Read public key from a FILE in PEM format.
     *
     * same goes on with bio, but with bio, it'll read from the bio, not from a file
     *
     * Source: https://stackoverflow.com/questions/7818117/why-i-cant-read-openssl-generated-rsa-pub-key-with-pem-read-rsapublickey
     */
    RSA* pubkey;
    try {
        pubkey = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);
    } catch (std::exception &e) {
        // something is funky, use PEM_read_bio_RSA_PUBKEY instead
        pubkey = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    }

    // Free the BIO
    BIO_free(bio);

    // If pubkey doesn't exists / failed to get
    if (!pubkey) {
        QMessageBox box;

        QByteArray message = "Failed to parse the public key: ";
        message.append(ERR_error_string(ERR_get_error(), NULL));

        box.setText(message);
        box.exec();

        return; // Abort mission!
    }

    // Finally, we can encrypt the string
    // First, get the string
    QString data_to_encrypt = ui->encrypt_input->text();

    // Second, get the RSA length
    int rsaLen = RSA_size(pubkey);

    // Third, encrypt it
    unsigned char* result_ = (unsigned char*) malloc(rsaLen);
    unsigned char* payload_buf = (unsigned char*) data_to_encrypt.toLocal8Bit().constData();

    // We're going to use PKCS1 Padding
    int encrypted_length = RSA_public_encrypt(data_to_encrypt.length() - 1, payload_buf, result_, pubkey, RSA_PKCS1_PADDING);

    // Check if it fails
    if (encrypted_length == -1) {
        // meh it failed
        // Show a message box
        QMessageBox box;

        QByteArray message = "Failed to encrypt: ";
        message.append(ERR_error_string(ERR_get_error(), NULL));

        box.setText(message);
        box.exec();

        return; // Abort mission!
    }

    // Save the result to a QByteArray
    QByteArray result((char*) result_);

    qDebug() << result;

    // Oh yeah, free the result_, we don't want memory leaks
    free(result_);

    /* Finally, fourth, set the lineEdit to the encrypted text in base64 form
     *
     * Why base64? It's because this encrypted form is a random jumbled binary,
     * we want to make this easier to copy, so encode it in base64
     */
    ui->encrypt_output->setText(result.toBase64());
}

void MainWindow::on_decrypt_button_clicked() {
    // Decrypt the text!

    // Get the private key
    QByteArray private_key = ui->private_key_text->toPlainText().toUtf8();

    // Put it in a BIO
    BIO* bio = BIO_new_mem_buf(private_key, -1);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    // Then read the bio to get the public key
    RSA *prikey = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);

    // Free the BIO
    BIO_free(bio);

    // If prikey doesn't exists / failed to get
    if (!prikey) {
        QMessageBox box;

        QByteArray message = "Failed to parse the private key: ";
        message.append(ERR_error_string(ERR_get_error(), NULL));

        box.setText(message);
        box.exec();

        return; // Abort mission!
    }

    // BUG: There are some funky sutff while converting from unsigned char* -> char* -> Base64 -> char* -> unsigned char*

    // Finally, we can decrypt the string
    // First, get the string (don't forget to decode it in base64)
    QByteArray data_to_decrypt = QByteArray::fromBase64(ui->decrypt_input->text().toUtf8());

    qDebug() << data_to_decrypt;

    // Second, get the RSA length
    int rsaLen = RSA_size(prikey);

    // Third, decrypt it
    unsigned char* result_ = (unsigned char*) malloc(rsaLen);
    unsigned char* payload_buf = (unsigned char*) data_to_decrypt.constData();

    QByteArray d((char*) payload_buf);

    qDebug() << d;

    // We're going to use PKCS1 Padding
    int encrypted_length = RSA_private_decrypt(data_to_decrypt.length() - 1, payload_buf, result_, prikey, RSA_PKCS1_PADDING);

    // Check if it fails
    if (encrypted_length == -1) {
        // meh it failed
        // Show a message box
        QMessageBox box;

        QByteArray message = "Failed to decrypt: ";
        message.append(ERR_error_string(ERR_get_error(), NULL));

        box.setText(message);
        box.exec();

        return; // Abort mission!
    }

    // Save the result to a QByteArray
    QByteArray result((char*) result_);

    // Oh yeah, free the result_, we don't want memory leaks
    free(result_);

    /* Finally, fourth, set the lineEdit to the encrypted text in base64 form
     *
     * Why base64? It's because this encrypted form is a random jumbled binary,
     * we want to make this easier to copy, so encode it in base64
     */
    ui->decrypt_output->setText(result.toBase64());
}

void MainWindow::on_pushButton_clicked() {
    // Make the user choose how big the key will be
    QStringList items;
    items << "512" << "1024" << "2048" << "4096";

    bool ok;
    QString item = QInputDialog::getItem(this, tr("Key Size"),
                                             tr("Choose a key size:"), items, 0, false, &ok);

    // Check if this is not ok
    if (!ok) {
        qCritical() << "QInputDialog::getItem is not okay";

        QMessageBox box;
        box.setText("Failed to show a QInputDialog, unknown reason.");
        box.exec();

        return;
    }

    // Get the key length
    int key_length = atoi(item.toUtf8());

    // Create a file object, used to store these temporary files
    FILE *fp;

    // Create a bignumber (this should be a prime number)
    BIGNUM *e = BN_new();
    BN_dec2bn(&e, "8191");

    // And generate a key pair
    RSA *keypair = RSA_new();
    RSA_generate_key_ex(keypair, key_length, e, NULL);

    // Free the bignumber
    BN_free(e);


    // Get the public key path, this should be in a temporary directory
    QByteArray pub_path = QDir::tempPath().toUtf8();
    pub_path.append("/public_key");

    // Open the path and write to it
    fp = fopen(pub_path, "w");
    PEM_write_RSAPublicKey(fp, keypair);
    // Oh yeah close it
    fclose(fp);


    // Get the private key path, this should be in a temporary directory
    QByteArray pri_path = QDir::tempPath().toUtf8();
    pri_path.append("/private_key");

    // Open it, and write the private key in it
    fp = fopen(pri_path, "w");
    PEM_write_RSAPrivateKey(fp, keypair, NULL, NULL, NULL, NULL, NULL);
    // Then close it
    fclose(fp);

    // Free some stuff
    RSA_free(keypair);


    // Read those files
    QFile pub(pub_path);
    QFile pri(pri_path);

    // Open them
    if (!pub.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QMessageBox box;
        box.setText("Failed to open file");
        box.exec();

        return;
    }

    if (!pri.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QMessageBox box;
        box.setText("Failed to open file");
        box.exec();

        return;
    }

    // Read them
    QByteArray public_key = pub.readAll();
    QByteArray private_key = pri.readAll();

    // Close the files
    pub.close();
    pri.close();

    // Set the public key text and private key text to be these
    ui->public_key_text->insertPlainText(public_key);
    ui->private_key_text->insertPlainText(private_key);

    // aaand, remove the files
    QFile::remove(pub_path);
    QFile::remove(pri_path);
}
