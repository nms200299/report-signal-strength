# report-signal-strength
● BoB 9기 공통교육 네트워크 과제

● 특정 MAC의 신호 세기를 볼 수 있는 프로그램임.

● (이제.. 잘 수 있겠다..ㅠ)

## 기능
● 랜카드 Monitor Mode (모니터 모드) 자동 전환.

● QT 기반 GUI 그래프 지원 / CUI 지원

(그래프는 QCustomPlot 라이브러리 사용)

● 채널 옵션이 주어지지 않으면, 모든 채널 반복 탐색.


## 사용법
![use](https://user-images.githubusercontent.com/12112214/108315378-acd1e200-71fe-11eb-951c-274dab4322fc.png)

    ./deauth <interface> <mac> [-ch <channel>]

## 특정 Station에 대한 테스트
![station](https://user-images.githubusercontent.com/12112214/108315479-d25eeb80-71fe-11eb-9d0c-457b18c2e6e3.png)

Station과 AP의 거리를 멀리할 때는 신호 세기(dBm)가 낮아지고,

가까이 할 때는 신호세기가 높아지는 것을 볼 수 있음.

## 특정 AP에 대한 테스트
![KakaoTalk_20210218_153625915_01](https://user-images.githubusercontent.com/12112214/108315954-8791a380-71ff-11eb-8421-73ad9f5a936b.jpg)

집 안에서는 신호 세기가 높다가,

집 밖으로 이동하면 신호 세기가 낮아지는 것을 볼 수 있음.
