#include "mainwindow.h"
#include "ui_mainwindow.h"

// Qt Libraries
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
    } else {
        // Something is there, enable it
        ui->encrypt_button->setEnabled(true);
    }
}

void MainWindow::on_private_key_text_textChanged() {
    // Note: yes, this can be simplified, but making it like this can increase the code readability

    if (ui->private_key_text->toPlainText().trimmed() == "") {
        // Empty, disable the button
        ui->decrypt_button->setEnabled(false);
    } else {
        // Something is there, enable it
        ui->decrypt_button->setEnabled(true);
    }
}
