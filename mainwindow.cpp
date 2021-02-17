#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QDesktopServices>

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
}
