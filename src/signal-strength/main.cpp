#include "mainwindow.h"
#include <QApplication>
#include <stdio.h>
#include <pthread.h>// thread
#include <unistd.h> // sleep

struct Channel_loop{
    char number[4]={0,};
}; // 4byte

void *channel_loop_thread(void *arg){
    struct Channel_loop channel[32];
    FILE *fp = 0x00;
    char line[32];
    char monitormode[70];
    char dev[30];

    memcpy(dev,arg,30);
    memset(monitormode,0,70);
    sprintf(monitormode, "iwlist %s channel | grep [0-9][0-9].:",dev);
    // iwlist 문자열을 구성함.

    if ((fp = popen(monitormode,"r")) == 0x00){
        return 0;
    } // pipe로 해당 랜카드가 지원하는 채널 정보를 가져옴

    int i,max=0;
    while(fgets(line, 34, fp) != 0x00) {
        strtok(line,":");
        for (i=18; i<=20; i++){
            if (line[i] == 0x20) break;
            channel[max].number[i-18] = line[i];
        }
        max=max+1;
    } // 해당 채널 정보를 파싱하여 저장함.
    pclose(fp);

    i=0;
    max=max-1;

    while (true) {
        for (i=0; i<=max; i++){
            memset(monitormode,0,70);
            sprintf(monitormode, "iwconfig %s ch %s", dev, channel[i].number);
            system(monitormode);
            printf("※  %s번 채널 변경\n",channel[i].number);
            usleep(10000);
        }
    } // 채널 변경을 무한 반복
    return 0;
}


void usage() {
    printf("syntax: ./deauth <interface> <mac> [-ch <channel>]\n");
    printf("\n");
    printf("-ch 옵션으로 채널이 명시되지 않으면, 모든 채널을 돌면서 패킷을 수집합니다.\n");
    exit(0);
} // 사용 예시 출력 함수.

int main(int argc, char *argv[])
{
    if (argc <= 2) usage();

    char monitormode[70];
    memset(monitormode,0,70);
    sprintf(monitormode, "ifconfig %s down", argv[1]);
    system(monitormode);
    sprintf(monitormode, "iwconfig %s mode monitor", argv[1]);
    system(monitormode);
    sprintf(monitormode, "ifconfig %s up", argv[1]);
    system(monitormode);
     // 자동으로 모니터 모드로 전환

    pthread_t channel_loop_handle;
    int channel_loop_status;

    if (argc > 3){
        if (memcmp(argv[3],"-ch",3) == 0){
            sprintf(monitormode, "iwconfig %s ch %s", argv[1],argv[4]);
            system(monitormode);
            // 채널 옵션이 주어지면 채널 변경
        }
    } else {
        if (pthread_create(&channel_loop_handle, 0, channel_loop_thread, argv[1]) < 0){
            printf("Thread Create Error!");
            exit(0);
        }
        // 채널 옵션이 안주어지면 채널 무한 루프
    }

    QApplication a(argc, argv);
    MainWindow w;
    w.pcap_open(argv[1],argv[2]);
    w.show();
    a.exec();
    // QT GUI 객체 생성

    if (memcmp(argv[3],"-ch",3) != 0) pthread_join(channel_loop_handle,(void **)&channel_loop_status);
}
