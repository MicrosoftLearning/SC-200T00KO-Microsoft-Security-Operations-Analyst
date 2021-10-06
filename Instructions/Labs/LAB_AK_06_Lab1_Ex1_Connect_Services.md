# 모듈 6 - 랩 1 - 연습 1 - 데이터 커넥터를 사용하여 Azure Sentinel에 데이터 연결

## 랩 시나리오

Azure Sentinel을 구현한 회사에서 근무하는 보안 운영 분석자인 여러분은 조직에 있는 많은 데이터 원본의 로그 데이터를 연결하는 방법을 알아야 합니다. 조직에는 Microsoft 365, Microsoft 365 Defender, Azure 리소스, 비 Azure 가상 머신, 네트워크 어플라이언스의 데이터가 있습니다.

여러분은 Azure Sentinel 데이터 커넥터를 사용하여 다양한 원본의 로그 데이터를 통합하는 방법을 계획하고 있고, 조직의 각 데이터 원본을 적절한 Azure Sentinel 데이터 커넥터에 매핑하는 관리용 커넥터 계획을 작성해야 합니다.

**중요 경고!**  가상 머신 WIN1 및 WIN2는 모듈 7에서 사용됩니다.  가상 머신을 저장해 두세요.   가상 머신을 저장하지 않고 랩을 끝내면 WIN1과 WIN2에 커넥터를 다시 설치해야 합니다.

### 작업 1: Azure Sentinel 작업 영역 액세스

이 작업에서는 Azure Sentinel 작업 영역에 액세스합니다.

1. WIN1 가상 머신에 Admin으로 로그인합니다. 암호로는 **Pa55w.rd**를 사용합니다.  

2. Microsoft Edge 브라우저를 엽니다.

3. Edge 브라우저에서 Azure Portal https://portal.azure.com으로 이동합니다.

4. 랩 호스팅 공급자가 제공한 **테넌트 전자 메일** 계정을 복사하여 **로그인** 대화 상자에 붙여 넣은 후 **다음**을 선택합니다.

5. 랩 호스팅 공급자가 제공한 **테넌트 암호**를 복사하여 **암호 입력** 대화 상자에 붙여 넣은 후 **로그인**을 선택합니다.

6. Azure Portal의 검색 창에 *Sentinel*을 입력하고 **Azure Sentinel**을 선택합니다.

7. 이전 랩에서 만든 Azure Sentinel 작업 영역을 선택합니다.

### 작업 2: Azure Active Directory 커넥터 연결

이 작업에서는 Azure Sentinel에 Azure Active Directory 커넥터를 연결합니다.

1. 구성 영역에서 **데이터 커넥터**를 선택합니다.  데이터 커넥터 페이지의 목록에서 **Azure Active Directory** 커넥터를 선택합니다.

2. 커넥터 정보 블레이드에서 **커넥터 페이지 열기**를 선택합니다.

3. 구성 영역에서 **로그인 로그** 및 **감사 로그** 옵션을 선택하고 **변경 내용 적용**을 선택합니다.

### 작업 3: Azure Active Directory ID 보호 커넥터 연결

이 작업에서는 Azure Sentinel에 Azure Active Directory ID 보호 커넥터를 연결합니다.

1. 데이터 커넥터 탭의 목록에서 **Azure Active Directory ID 보호** 커넥터를 선택합니다.

2. 커넥터 정보 블레이드에서 **커넥터 페이지 열기**를 선택합니다.

3. 구성 영역에서 **연결** 단추를 선택합니다.

### 작업 4: Azure Defender 커넥터 연결

이 작업에서는 Azure Defender 커넥터를 연결합니다.

1. 데이터 커넥터 탭의 목록에서 **Azure Defender** 커넥터를 선택합니다.

2. 커넥터 정보 블레이드에서 **커넥터 페이지 열기**를 선택합니다.

3. 구독 아래 구성 영역에서 Azure 구독을 선택하고 **연결**을 클릭합니다.

4. "연결" 메시지를 읽고 **확인**을 선택하여 계속합니다. Azure 구독 상태가 이제 *연결됨*이어야 합니다.

5. 인시던트 만들기 - 권장! 영역에서 **사용**을 선택합니다.

### 작업 5: Microsoft Cloud App Security 커넥터 연결

이 작업에서는 Microsoft Cloud App Security 커넥터를 연결합니다.

1. 데이터 커넥터 탭의 목록에서 **Microsoft Cloud App Security** 커넥터를 선택합니다.

2. 커넥터 정보 블레이드에서 **커넥터 페이지 열기**를 선택합니다.

3. **경고**, **변경 내용 적용**을 차례로 선택합니다.

### 작업 6: Office 365용 Microsoft Defender 커넥터 연결

이 작업에서는 Office 365용 Microsoft Defender 커넥터를 연결합니다.

1. 데이터 커넥터 탭의 목록에서 **Office 365용 Microsoft Defender(미리 보기)** 커넥터를 선택합니다.

2. 커넥터 정보 블레이드에서 **커넥터 페이지 열기**를 선택합니다.

3. 구성 영역에서 **연결**을 선택합니다.

### 작업 7: Microsoft Defender for Identity 커넥터 연결

이 작업에서는 Microsoft Defender for Identity 커넥터를 검토합니다.

1. 데이터 커넥터 탭의 목록에서 **Microsoft Defender for Identity** 커넥터를 선택합니다.

2. 커넥터 정보 블레이드에서 **커넥터 페이지 열기**를 선택합니다.

3. 연결 옵션을 검토합니다. 옵션을 검토만 하고 연결하지는 마세요. 연결 정보만 파악하면 됩니다.

### 작업 8: 엔드포인트용 Microsoft Defender 커넥터 연결

이 작업에서는 엔드포인트용 Microsoft Defender 커넥터를 연결합니다.

1. 데이터 커넥터 탭의 목록에서 **엔드포인트용 Microsoft Defender** 커넥터를 선택합니다.

2. 커넥터 정보 블레이드에서 **커넥터 페이지 열기**를 선택합니다.

3. 구성 영역에서 **연결**을 선택합니다.

### 작업 9: Microsoft 365 Defender 커넥터 연결

이 작업에서는 Microsoft 365 Defender 커넥터를 연결합니다.

1. 데이터 커넥터 탭의 목록에서 **Microsoft 365 Defender(미리 보기)** 커넥터를 선택합니다.

2. 커넥터 정보 블레이드에서 **커넥터 페이지 열기**를 선택합니다.

3. 엔드포인트용 Microsoft Defender의 체크박스를 모두 선택합니다.

4. **변경 내용 적용**을 선택합니다.

## 연습 2 계속 진행
