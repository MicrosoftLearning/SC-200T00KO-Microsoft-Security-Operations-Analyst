---
lab:
    title: '연습 2 - 플레이북 만들기'
    module: '모듈 7 - Microsoft Sentinel을 사용하여 검색 만들기 및 조사 수행'
---

# 모듈 7 - 랩 1 - 연습 2 - 플레이북 만들기


### 작업 1: Microsoft Teams에서 보안 운영 센터 팀 만들기

이 작업에서는 랩에 사용할 Microsoft Teams 팀을 만듭니다.

1. WIN1 가상 머신에 Admin으로 로그인합니다. 암호로는 **Pa55w.rd**를 사용합니다.  

2. Edge 브라우저에서 새 탭을 열고 Microsoft Teams 포털 (https://teams.microsoft.com) 로 이동합니다.

3. 랩 호스팅 공급자가 제공한 **테넌트 전자 메일** 계정을 복사하여 **로그인** 대화 상자에 붙여넣은 후 **다음**을 선택합니다.

4. 랩 호스팅 공급자가 제공한 **테넌트 암호**를 복사하여 **암호 입력** 대화 상자에 붙여넣은 후 **로그인**을 선택합니다.

5. Teams 팝업이 표시되면 닫습니다.

6. 아직 선택하지 않은 경우 왼쪽 메뉴에서 **팀**을 선택하고 아래쪽의 **팀 가입 또는 만들기**를 선택합니다.

7. 기본 창에서 **팀 만들기** 단추를 선택합니다.

8. **처음부터** 단추를 선택합니다.

9. **프라이빗** 단추를 선택합니다.

10. 팀 이름을 **SOC**로 입력하고 **만들기** 단추를 선택합니다.

11. SOC 화면에 구성원을 추가하고 **건너뛰기** 단추를 선택합니다. 

12. 새로 만든 SOC 옆에 있는 **[...]** 를 선택하고 **채널 추가**를 선택합니다.

13. 채널 이름을 *New Alerts*로 입력하고 **추가** 단추를 선택합니다.


### 작업 2: Microsoft Sentinel에서 플레이북 만들기

이 작업에서는 Microsoft Sentinel에서 플레이북으로 사용할 논리 앱을 만듭니다.

1. Edge 브라우저에서 Azure Portal https://portal.azure.com 으로 이동합니다.

2. 랩 호스팅 공급자가 제공한 **테넌트 전자 메일** 계정을 복사하여 **로그인** 대화 상자에 붙여넣은 후 **다음**을 선택합니다.

3. 랩 호스팅 공급자가 제공한 **테넌트 암호**를 복사하여 **암호 입력** 대화 상자에 붙여넣은 후 **로그인**을 선택합니다.

4. Azure Portal의 검색 창에 *Sentinel*을 입력하고 **Microsoft Sentinel**을 선택합니다.

5. 앞에서 만든 Microsoft Sentinel 작업 영역을 선택합니다.

6. 페이지 왼쪽의 *구성 관리* 영역에서 **커뮤니티** 페이지를 선택합니다.

7. 오른쪽 창에서 **커뮤니티 콘텐츠 온보딩** 링크를 선택합니다. Edge 브라우저에 Microsoft Sentinel GitHub 콘텐츠용 새 탭이 열립니다.

8. **Playbooks** 폴더를 선택합니다.

9. **Post-Message-Teams** 폴더를 선택합니다.

10. readme.md 상자의 두 번째 *빠른 배포* 옵션 **경고 트리거로 배포**에서 **Azure에 배포** 단추를 선택합니다.  

    >**중요**: 인시던트와 경고 두 개의 Microsoft Sentinel 경고가 있습니다. 경고(두 번째) 트리거를 선택해야 합니다.

11. Azure 구독이 선택되어 있는지 확인합니다.

12. 리소스 그룹에서 **새로 만들기**를 선택하고 *RG-Playbooks*를 입력한 후 **확인**을 선택합니다.

13. 지역에서는 상황에 맞는 지역을 선택합니다. 기본 지역을 사용하는 것이 가장 효율적일 가능성이 높습니다.

14. *플레이북 이름*이 "PostMessageTeams-OnAlert"인지 확인하고 **검토 + 만들기**를 선택합니다.

15. 이제 **만들기**를 선택합니다.

    >**참고:** 다음 작업으로 진행하기 전에 배포가 완료될 때까지 기다립니다. 배포하는 데 몇 분이 걸릴 수 있습니다.


### 작업 3: Microsoft Sentinel에서 플레이북 만들기

이 작업에서는 만든 새 플레이북을 적절한 연결 정보로 업데이트합니다.

1. Azure Portal의 검색 창에 *Sentinel*을 입력하고 **Microsoft Sentinel**을 선택합니다.

2. Microsoft Sentinel 작업 영역을 선택합니다.

3. 구성 영역에서 **자동화**를 선택하고 **활성 플레이북** 탭을 선택합니다.

4. **PostMessageTeams-OnAlert** 플레이북을 선택합니다.

5. *PostMessageTeams-OnAlert*의 논리 앱 페이지 가운데 메뉴에서 **편집**을 선택합니다.

6. *첫 번째* **Microsoft Sentinel 경고에 대한 대응이 트리거된 경우** 블록을 선택합니다.

7. **연결 변경** 링크를 선택합니다.

8. **새 항목 추가**를 선택하고 **로그인**을 선택합니다. 메시지가 표시되면 새 창에서 Azure 구독 관리자 자격 증명으로 로그인합니다.

9. 이제 *두 번째* **경고 - 인시던트 가져오기** 블록을 선택합니다.

10. **연결 변경** 링크를 선택합니다.

11. *표시 이름* 아래의 Azure 구독 관리자 자격 증명이 있는 연결을 선택합니다. **힌트:** admin@ZZZZZZ.onmicrosoft.com.

12. 이제 *세 번째* **연결** 블록을 선택합니다.

13. **새 항목 추가**를 선택하고 메시지가 표시되면 Azure 구독 관리자 자격 증명을 선택합니다.

14. 이제 **메시지 게시(V3)** 블록에서 팀 상자 끝부분의 **X**를 선택하여 콘텐츠를 지웁니다. 편집 상자가 Microsoft Teams에서 사용 가능한 팀 목록이 포함된 드롭다운으로 변경됩니다.  **SOC**를 선택합니다.

15. 마찬가지로, 채널에서 편집 상자 끝부분의 **X**를 선택하여 콘텐츠를 지웁니다. 편집 상자가 채널 목록이 포함된 드롭다운으로 변경됩니다. **새 경고**를 선택합니다.

16. 명령 모음에서 **저장**을 선택합니다.

이후의 랩에서 이 논리 앱을 사용할 예정입니다.

## 연습 3 계속 진행
