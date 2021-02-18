#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QTimer>
//###########################
#include <stdio.h>
#include <unistd.h> // sleep
#include <pcap.h>   // pcap
#include <stdlib.h> // exit
#include <string.h> // memcpy, memcmp, memset, strcat
//###########################
#include <802.11.h>

struct pcap_pkthdr* header;
const u_char* packet;
uint8_t compare_mac[6];
pcap_t* handle;

double data_x[600], data_y[600];
uint32_t data_index=0;
struct Radiotap_2* radiotap_2;

void char2byte(char *argv){
// 맥 주소를 char 형식에서 int 형식으로 바꿔줍니다.
// (ex. FF:FF:FF:FF:FF:FF -> 255 255 255 255 255 255
    uint8_t j, count=0;
    int save=0;
    char temp[17];
    if (strlen(argv) == 17){ //  숫자, 문자, 특수문자 총 17자
        memcpy(temp, argv, 17);
        for (j=0; j<=16; j++){
        if (islower(temp[j]) != 0) temp[j] = temp[j]-32; // 소문자면 대문자로 치환
            if (count == 0){ // 두 번째 자리 수이면, (ex. X0)
                if ((temp[j] >= 65) && (temp[j] <= 70)){ // (대)문자의 경우,
                    save = save + 160 + ((temp[j] - 65) * 16);
                } else if ((temp[j] >= 48) && (temp[j] <= 57)) {
                    save = save + ((temp[j] - 48) * 16); // 숫자의 경우,
                } else {
                    exit(0);
                }
                count = 1;
            } else { // 첫 번째 자리 수이면, (ex. 0X)
                if ((temp[j] >= 65) && (temp[j] <= 70)){
                    save = save + (temp[j] - 55);  //  (대)문자의 경우,
                } else if ((temp[j] >= 48) && (temp[j] <= 57)) {
                    save = save + ((temp[j] - 48)); // 숫자의 경우,
                } else {
                    exit(0);
                }
                j=j+1;
                count = 0;
                compare_mac[j/3] = save;
                save = 0;
            }
        }
    } else {
        exit(0);
    }
}

void MainWindow::pcap_open(char *dev, char *mac){
    char errbuf[PCAP_ERRBUF_SIZE];

    char2byte(mac);
    // MAC 주소 파싱 (FF:FF:FF:FF:FF:FF -> FFFFFFFFFFFF)

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    // 인자 값으로 받은 네트워크 장치를 사용해 promiscuous 모드로 pcap를 연다.

    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        exit(0);
    } // 열지 못하면 메세지 출력 후 종료.
}

void MainWindow::pcap_read(){
    int res = pcap_next_ex(handle, &header, &packet);
    // 다음 패킷을 잡고 성공시 1을 반환한다.

    if (res == -1 || res == -2) {
        printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
        exit(0);
    } // 에러와(-1), EOF(-2)시 종료한다.

    struct Radiotap_1* radiotap_1;
    radiotap_1 = (Radiotap_1*)packet;
    packet = packet + sizeof(Radiotap_1);
    radiotap_1->header_length = radiotap_1->header_length - sizeof(Radiotap_1);
    //  radiotap_1 정보를 구함.

    bool TSFT_Check = false;
    while (radiotap_1->header_presentflag[3] >> 7 == 1) {
        if (radiotap_1->header_presentflag[0] % 2 == 1) TSFT_Check = true;
        // presentflag Ext(확장) 비트가 0이 아닌 flag도
        // TSFT 비트가 활성화 되어 있는지 체크.
        memcpy (radiotap_1->header_presentflag, packet, 4);
        packet = packet + sizeof(radiotap_1->header_presentflag);
        radiotap_1->header_length = radiotap_1->header_length - sizeof(radiotap_1->header_presentflag);
    } // presentflag Ext(확장) 비트가 0이 될 때까지 다음 4byte씩 체크.

    if (radiotap_1->header_presentflag[0] % 2 == 1) TSFT_Check = true;
    // presentflag Ext(확장) 비트가 0인 flag도
    // TSFT 비트가 활성화 되어 있는지 체크.

    if (TSFT_Check == true) {
        packet = packet + 8;
        radiotap_1->header_length = radiotap_1->header_length - 8;
    } // TSFT비트가 활성화 되어 있으면 TIME STAMP 태그 8byte만큼 넘김.

    radiotap_2 = (Radiotap_2*)packet;
    packet = packet + sizeof(Radiotap_2);
    // radiotap_2 정보를 구함.

    radiotap_1->header_length = radiotap_1->header_length - sizeof(Radiotap_2);
    packet = packet + radiotap_1->header_length;
    // Radiotap 필드를 건너 뜀.

    struct IEEE_802_11* ieee_802_11;
    ieee_802_11 = (IEEE_802_11*)packet;
    // ieee.802.11 정보를 구함.

    switch (ieee_802_11->type[0]) {
    // type이 아래 정보 중 하나라면,

    case 0x80: // Beacon Frame
    case 0x94: // Block ACK
    case 0xD0: // Action
    case 0xB0: // Authentication
    case 0x20: // Reassociation Request
    case 0x40: // Probe Request
    case 0x50: // Probe Response
    // (ds switch)
    //      	form ds     ->  sta(dest)   bssid       source (ta = bssid) (ta 오프셋 위치가 동일..)
    //          to ds       ->  bssid       sta(source) dest   (ta = sa)    (ta 오프셋 위치가 동일..)
    case 0x08: // Data
    case 0x48: // Null Function
    case 0x88: // QoS
        if (memcmp(ieee_802_11->addr2, compare_mac, 6) == 0) {
        // 맥주소 비교 후, 맞으면 출력
            printf("Packet Detect! [%02X:%02X:%02X:%02X:%02X:%02X] %ddBM  ", compare_mac[0], compare_mac[1],
                    compare_mac[3], compare_mac[4], compare_mac[5], compare_mac[6], radiotap_2->antenna_signal-256);
            switch (ieee_802_11->type[0]) {
            // (ta = sa)
            case 0x80:
                printf("Beacon Frame"); break;
            case 0x94:
                printf("Block ACK"); break;
            case 0xD0:
                printf("Action"); break;
            case 0xB0:
                printf("Authentication"); break;
            case 0x20:
                printf("Reassociation Request"); break;
            case 0x40:
                printf("Probe Request"); break;
            case 0x50:
                printf("Probe Response"); break;
            case 0x08:
                printf("Data");
                if (ieee_802_11->type[1] % 2 == 0){
                    printf(" (To DS)");
                } else {
                    printf(" (From DS)");
                } break;
            case 0x48:
                printf("Null Function");
                if (ieee_802_11->type[1] % 2 == 0){
                    printf(" (To DS)");
                } else {
                    printf(" (From DS)");
                } break;
            case 0x88:
                printf("QoS");
                if (ieee_802_11->type[1] % 2 == 0){
                    printf(" (To DS)");
                } else {
                    printf(" (From DS)");
                } break;
            }
            printf("\n");

            Chart_Draw();
            // 차트를 출력함.
        }
        break;
    }
}

void MainWindow::Chart_Draw(){

    if (data_index == 0){
        data_x[data_index] = 1;
    } else {
        data_x[data_index] = data_index + 1;
    } // 배열 시작은 0번 부터, 좌표 시작은 1번 부터.
    data_y[data_index] = radiotap_2->antenna_signal;
    // Y축에 신호 세기 정보를 기록.

    data_index++;
    if (data_index == 600){
        data_index = 0;
        memset(data_x,0,sizeof(data_x));
        memset(data_y,0,sizeof(data_y));
    } // 인덱스가 오버나면 인덱스와 데이터를 초기화

    QVector<double> x(600,0), y(600,0);
    for (int var=0; var<=data_index; var++) {
        x[var] = data_x[var];
        y[var] = data_y[var]-256;
    } // double형식 좌표 데이터를 QVector double형식으로 복사

    ui->widget->graph(0)->setData(x, y);
    ui->widget->replot();
    // 차트를 그림. (qcustomplot 라이브러리 사용)
}


MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    // MainWindow 기본 셋팅

    ui->widget->addGraph();
    ui->widget->xAxis->setLabel("Index");
    ui->widget->yAxis->setLabel("-dBm");
    ui->widget->xAxis->setRange(1, 600);
    ui->widget->yAxis->setRange(-100, 0);
    // 차트 정보 구성

    memset(data_x,0,sizeof(data_x));
    memset(data_y,0,sizeof(data_y));
    // 좌표 데이터 초기화

    QTimer *m_timer = new QTimer(this);
    connect( m_timer, SIGNAL(timeout()), this, SLOT(pcap_read()));
    m_timer->start(1);
    // qt 타이머 객체를 생성하여, 0.001초 마다 패킷 캡처 함수를 호출
}


MainWindow::~MainWindow()
{
    delete ui;
    // MainWindow 기본 셋팅
}
