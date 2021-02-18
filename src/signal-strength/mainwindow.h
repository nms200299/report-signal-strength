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
    void pcap_open(char *dev, char *mac);
    // 이 친구는 main함수에서 호출될 것이기 때문에 public으로.

private slots:
    void pcap_read();
    void Chart_Draw();
    // 이 친구들은 mainwindow 내부에서 사용하기 위해.

private:
    Ui::MainWindow *ui;

};
#endif // MAINWINDOW_H
