# 모듈 7 - 랩 1 - 연습 3 - 예약된 쿼리 만들기

### 작업 1: 예약된 쿼리 만들기

이 작업에서는 예약된 쿼리를 만들고 이를 이전 연습에서 만든 Teams 채널에 연결합니다.

1. WIN1 가상 머신에 Admin으로 로그인합니다. 암호로는 **Pa55w.rd**를 사용합니다.  

2. 랩 호스팅 공급자가 제공한 **테넌트 전자 메일** 계정을 복사하여 **로그인** 대화 상자에 붙여 넣은 후 **다음**을 선택합니다.

3. 랩 호스팅 공급자가 제공한 **테넌트 암호**를 복사하여 **암호 입력** 대화 상자에 붙여 넣은 후 **로그인**을 선택합니다.

4. Azure Portal의 검색 창에 *Sentinel*을 입력하고 **Azure Sentinel**을 선택합니다.

5. Azure Sentinel 작업 영역을 선택합니다.

6. 구성 영역에서 **분석**을 선택합니다.

7. **+ 만들기** 단추를 선택하고 **예약된 쿼리 규칙**을 선택합니다.

8. Analytics 규칙 마법사의 일반 탭에서 이름으로 *Inactive Account sign in attempts*를 입력합니다.

9. 전술로는 **초기 액세스**를 선택합니다.

10. 심각도로는 **중간**을 선택합니다.

11. **다음: 규칙 논리 설정 >** 단추를 선택합니다.

12. 규칙 쿼리에 다음 KQL 문을 붙여넣습니다.

```KQL
SigninLogs
| where ResultType == "50057"
| where ResultDescription =~ "User account is disabled. The account has been disabled by an administrator."
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), count(), applicationCount = dcount(AppDisplayName), 
applicationSet = makeset(AppDisplayName) by UserPrincipalName, IPAddress
| extend timestamp = StartTimeUtc, AccountCustomEntity = UserPrincipalName, IPCustomEntity = IPAddress
```

**경고:** 가상 머신에 붙여넣기 기능을  사용할 때는 | (파이프) 문자를 더 추가할 수 있습니다.  앞의 KQL 문과 같이 붙여 넣은 항목을 확인합니다.

**참고:** "쿼리 결과 보기" 링크를 선택하면 결과가 반환되지 않아야 합니다.  그리고 오류도 발생하지 않아야 합니다.  

13. 쿼리 예약 영역의 분석 규칙 마법사 - 새 규칙 만들기 블레이드로 돌아와서 *쿼리 실행 간격* 에 **5**를 입력하고 단위로는 **분**을 선택합니다.

14. 쿼리 예약 영역의 *마지막 옵션에서 조회 데이터*에 **1**을 입력하고 단위로는 **일**을 선택합니다.

15. 경고 임계값 영역의 옵션은 변경하지 않고 그대로 유지합니다.

**참고:** 모범 사례에 따라 경고 규칙 KQL 쿼리 문의 임계값을 관리해야 합니다.

16. 이벤트 그룹화 영역에서 **모든 이벤트를 단일 경고로 그룹화** 옵션을 선택된 상태로 유지합니다.

17. **다음: 인시던트 설정 >** 단추를 클릭합니다.  

18. 인시던트 설정 탭에서 기본 옵션을 검토합니다.

19. **다음: 자동화된 응답 >** 단추를 클릭합니다.

20. 경고 자동화 영역의 자동화된 응답 탭에서 이전 연습에서 만든 *PostMessageTeams-OnAlert* 플레이북을 선택합니다.

22. **다음: 검토 >** 단추를 선택합니다.
  
23. **만들기**를 선택합니다.

### 작업 2: 새 규칙 테스트

이 작업에서는 새 예약된 쿼리 규칙을 테스트합니다.

1. Azure Portal의 검색 창에 *Azure Active Directory*를 입력합니다. 그런 다음 **Azure Active Directory**를 선택합니다.

2. 관리 영역에서 **사용자**를 선택합니다.

3. 목록에서 **Christie Cline** 사용자를 선택하면 Christie Cline | 프로필 페이지가 표시됩니다.

4. 명령 모음에서 **편집**을 선택합니다.

5. 설정 영역에서 **로그인 차단**을 **예**로 변경합니다.

6. 이제 명령 모음에서 **저장**을 선택합니다.

7. Azure Portal에서 오른쪽 위의 사용자 아바타를 선택하여 로그아웃합니다.

8. 브라우저를 닫습니다.

9. Microsoft Edge의 새 비공개 탐색 세션을 열고 https://portal.office.com으로 이동하여 사용자 ChristieC@**Tenant 전자 메일 도메인으로 로그인을 시도합니다.** 암호는 관리자의 테넌트 암호와 동일해야 합니다.  계정이 차단되었다는 경고가 표시됩니다. 이 작업에 문제가 없으면 경고를 트리거해야 합니다.

10. 브라우저를 닫습니다. 마지막 단계에서 트리거된 경고를 처리하는 데 10분 정도 걸릴 수 있습니다. 다음 연습을 계속 진행하다가 나중에 이 지점으로 돌아와도 됩니다.

11. Edge 브라우저에서 Azure Portal https://portal.azure.com으로 이동합니다.

12. 랩 호스팅 공급자가 관리 사용자용으로 제공한 **테넌트 전자 메일** 계정을 복사하여 **로그인** 대화 상자에 붙여넣은 후 **다음**을 선택합니다.

13. 랩 호스팅 공급자가 관리 사용자용으로 제공한 **테넌트 암호**를 복사하여 **암호 입력** 대화 상자에 붙여넣은 후 **로그인**을 선택합니다.

14. Azure Portal의 검색 창에 *Sentinel*을 입력하고 **Azure Sentinel**을 선택합니다.

15. Azure Sentinel 작업 영역을 선택합니다.

16. **인시던트** 메뉴 옵션을 선택합니다.

17. 새로 만든 인시던트가 표시됩니다.  인시던트를 선택하고 오른쪽 블레이드의 정보를 검토합니다.

18. 브라우저 탭을 열고 https://teams.microsoft.com로 이동하여 Microsoft Teams를 엽니다. *SOC* 팁으로 이동하여 인시던트에 대한 메시지가 게시되었는지 확인합니다.

## 연습 4 계속 진행
