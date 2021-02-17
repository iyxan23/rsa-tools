#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_pushButton_5_released();

    void on_openfile_public_key_clicked();

    void on_openfile_private_key_clicked();

    void on_public_key_text_textChanged();

    void on_private_key_text_textChanged();

    void on_encrypt_button_clicked();

    void on_decrypt_button_clicked();

private:
    Ui::MainWindow *ui;

    bool public_key_exists;
    bool private_key_exists;
};
#endif // MAINWINDOW_H
