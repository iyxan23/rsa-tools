#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QDesktopServices>
#include <QMessageBox>
#include <QFileDialog>
#include <QDir>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow) {
    ui->setupUi(this);
}

MainWindow::~MainWindow() {
    delete ui;
}


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
