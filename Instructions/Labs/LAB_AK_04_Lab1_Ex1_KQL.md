# 모듈 4 - 랩 1 - 연습 1 - KQL(Kusto 쿼리 언어)을 사용하여 Azure Sentinel용 쿼리 만들기

## 랩 시나리오
Azure Sentinel을 구현한 회사에서 근무하는 보안 작업 분석가인 여러분은 로그 데이터 분석을 수행하여 악의적인 활동을 검색하고 시각화를 표시하고 위협 헌팅을 수행할 책임이 있습니다. 로그 데이터를 쿼리하려면 KQL(Kusto Query Language)을 사용합니다.

### 작업 1: KQL 테스트 영역 액세스

이 작업에서는 KQL 문 작성을 연습할 수 있는 Log Analytics 환경에 액세스합니다.

1. WIN1 가상 머신에 Admin으로 로그인합니다. 암호로는 **Pa55w.rd**를 사용합니다.  

2. 브라우저에서 https://aka.ms/lademo로 이동합니다. MOD 관리자 자격 증명을 사용하여 로그인합니다. 

3. 화면 왼쪽 탭에 나열되어 있는 사용 가능한 테이블을 살펴봅니다.

4. 쿼리 편집기에서 다음 쿼리를 입력하고 실행 단추를 선택합니다.  아래쪽 창에서 쿼리 결과가 표시됩니다.

```KQL
SecurityEvent
```

5. 첫 번째 레코드 다음의 **>** 를 선택하여 해당 행의 정보를 확장합니다.

### 작업 2: 기본 KQL 문 실행

이 작업에서는 기본적인 KQL 문을 작성합니다.

**참고:**  각 단계에 대해 쿼리 창에서 이전 문을 지우거나, 마지막으로 연 탭 후에 **+**를 선택함으로써 새 쿼리 창을 엽니다(최대 25개).

1. 다음 문에는 let 문을 사용하여 변수를 선언하는 방법이 나와 있습니다. 쿼리 창에서 다음 문을 입력하고 **실행**을 선택합니다. 


```KQL
let timeOffset = 7d;
let discardEventId = 4688;
SecurityEvent
| where TimeGenerated > ago(timeOffset*2) and TimeGenerated < ago(timeOffset)
| where EventID != discardEventId
```

2. 다음 문에는 let 문을 사용하여 동적 목록을 선언하는 방법이 나와 있습니다. 쿼리 창에서 다음 문을 입력하고 **실행**을 선택합니다. 


```KQL
let suspiciousAccounts = datatable(account: string) [
    @"\administrator", 
    @"NT AUTHORITY\SYSTEM"
];
SecurityEvent | where Account in (suspiciousAccounts)
```

3. 다음 문에는 "let" 문을 사용하여 동적 테이블을 선언하는 방법이 나와 있습니다. 쿼리 창에서 다음 문을 입력하고 **실행**을 선택합니다. 

```KQL
let LowActivityAccounts =
    SecurityEvent 
    | summarize cnt = count() by Account 
    | where cnt < 10;
LowActivityAccounts | where Account contains "Mal"
```

**참고:** 이 스크립트를 실행하면 결과가 반환되지 않습니다.

4. 다음 문에는 모든 테이블과 열에서 쿼리 창에 표시되는 쿼리 시간 범위 내의 레코드를 검색하는 방법이 나와 있습니다. 쿼리 창에서 이 스크립트를 실행하기 전에 **Time range**를 "Last hour"로 변경합니다. 다음 문을 입력하고 **실행**을 선택합니다. 

```KQL
search "err"
```

**경고:** 다음 스크립트를 실행할 때는 TIme 범위를 "Last 24 hours"로 다시 변경해야 합니다.

5. 다음 문에는 "in" 절을 사용하여 나열한 테이블에서 쿼리 창에 표시되는 쿼리 시간 범위 내의 레코드를 검색하는 방법이 나와 있습니다. 쿼리 창에서 다음 문을 입력하고 **실행**을 선택합니다. 

```KQL
search in (SecurityEvent,SecurityAlert,A*) "err"
```


6. 다음 문에는 where 연산자를 사용하는 필터 사용 방식이 나와 있습니다. 쿼리 창에서 다음 문을 입력하고 **실행**을 선택합니다. 

**참고:** 아래의 각 코드 블록에서 쿼리를 입력한 후 "실행"을 선택해야 합니다.

```KQL
SecurityEvent
| where TimeGenerated > ago(1d)
```

```KQL
SecurityEvent
| where TimeGenerated > ago(1h) and EventID == "4624"
```

```KQL
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4624
| where AccountType =~ "user"
```

```KQL
SecurityEvent | where EventID in (4624, 4625)
```


7. 다음 문에는 쿼리 창에서 extend 연산자를 사용하여 필드를 만드는 방법이 나와 있습니다. 다음 문을 입력하고 **실행**을 선택합니다. 


```KQL
SecurityAlert
| where TimeGenerated > ago(7d)
| extend severityOrder = case (
    AlertSeverity == "High", 3,
    AlertSeverity == "Medium", 2, 
    AlertSeverity == "Low", 1,
    AlertSeverity == "Informational", 0,
    -1)
```


8. 다음 문에는 extend를 사용하여 let, 동적 목록 만들기 및 필드 만들기를 모두 실행하는 실제 예제가 나와 있습니다. 쿼리 창에서 다음 문을 입력하고 **실행**을 선택합니다. 

```KQL
let timeframe = 1d;
let DomainList = dynamic(["tor2web.org", "tor2web.com"]);
Syslog
| where TimeGenerated >= ago(timeframe)
| where ProcessName contains "squid"
| extend 
  HTTP_Status_Code = extract("(TCP_(([A-Z]+)…-9]{3}))",8,SyslogMessage),    
  Domain = extract("(([A-Z]+ [a-z]{4…Z]+ )([^ :\\/]*))",3,SyslogMessage)
| where HTTP_Status_Code == "200"
| where Domain contains "."
| where Domain has_any (DomainList)
```

**참고:** 이 스크립트를 실행하면 결과가 반환되지 않습니다.

9. 다음 문에는 order by 연산자를 사용하여 결과를 정렬하는 방법이 나와 있습니다. 쿼리 창에서 다음 문을 입력하고 **실행**을 선택합니다. 


```KQL
SecurityAlert
| where TimeGenerated > ago(7d)
| extend severityOrder = case (
    AlertSeverity == "High", 3,
    AlertSeverity == "Medium", 2, 
    AlertSeverity == "Low", 1,
    AlertSeverity == "Informational", 0,
    -1)
| order by severityOrder desc
```

10. 다음 문에는 프로젝트 연산자를 사용하여 결과 집합을 필드를 지정하는 방법이 나와 있습니다.

**참고:** 아래의 각 코드 블록에서 쿼리를 입력한 후 "실행"을 선택해야 합니다.

쿼리 창에서 다음 문을 입력하고 **실행**을 선택합니다. 


```KQL
SecurityEvent
| project Computer, Account
```



```KQL
SecurityAlert
| where TimeGenerated > ago(7d)
| extend severityOrder = case (
    AlertSeverity == "High", 3,
    AlertSeverity == "Medium", 2, 
    AlertSeverity == "Low", 1,
    AlertSeverity == "Informational", 0,
    -1)
| order by severityOrder
| project-away severityOrder
```

### 작업 3: Summarize 연산자를 사용하여 KQL에서 결과 분석

이 작업에서는 데이터를 준비하는 KQL 문을 작성합니다.

1. 다음 문에는 count 함수 사용법이 나와 있습니다. 쿼리 창에서 다음 문을 입력하고 **실행**을 선택합니다. 



```KQL
SecurityEvent
| where EventID == "4688"
| summarize count() by Process, Computer
```


2. 다음 문에는 count 함수 사용법이 나와 있습니다. 쿼리 창에서 다음 문을 입력하고 **실행**을 선택합니다. 


```KQL
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4624
| summarize cnt=count() by AccountType, Computer
```



3. 다음 문에는 dcount 함수 사용법이 나와 있습니다. 쿼리 창에서 다음 문을 입력하고 **실행**을 선택합니다. 


```KQL
SecurityEvent
| summarize dcount(IpAddress)
```

4. 다음 문은 암호 스프레이 시도를 감지하는 Azure Sentinel 분석 규칙입니다.

처음 세 "where" 연산자는 실패한 로그인에 대한 결과 집합을 비활성화된 계정으로 필터링합니다.  그런 다음 해당 문은 애플리케이션 이름과 사용자별 그룹 IP 주소에 대한 고유 카운트를 “요약”합니다.  마지막으로 생성된 변수(임계값)를 검사하여 숫자가 허용된 크기를 초과하는지 확인합니다. 쿼리 창에서 다음 문을 입력하고 **실행**을 선택합니다. 


```KQL
let timeframe = 1d;
let threshold = 3;
SigninLogs
| where TimeGenerated >= ago(timeframe)
| where ResultType == "50057"
| where ResultDescription =~ "User account is disabled. The account has been disabled by an administrator."
| summarize applicationCount = dcount(AppDisplayName) by UserPrincipalName, IPAddress
| where applicationCount >= threshold
```

**참고:** 이 스크립트를 실행하면 결과가 반환되지 않습니다.

5. 다음 문에는 arg_max 함수 사용법이 나와 있습니다.

다음 문은 컴퓨터 SQL12.NA.contosohotels.com에 대한 SecurityEvent 테이블에서 최신 행을 반환합니다.  arg_max 함수의 *는 해당 행의 모든 열을 요청합니다. 쿼리 창에서 다음 문을 입력하고 **실행**을 선택합니다. 


```KQL
SecurityEvent 
| where Computer == "SQL12.na.contosohotels.com"
| summarize arg_max(TimeGenerated,*) by Computer
```

6. 다음 문에는 arg_min 함수 사용법이 나와 있습니다.

이 문에서는 컴퓨터 SQL12.NA.contosohotels.com의 가장 오래된 SecurityEvent가 결과 집합으로 반환됩니다. 쿼리 창에서 다음 문을 입력하고 **실행**을 선택합니다. 


```KQL
SecurityEvent 
| where Computer == "SQL12.na.contosohotels.com"
| summarize arg_min(TimeGenerated,*) by Computer
```

7. 다음 문에는 파이프 "|"의 순서를 기준으로 결과를 파악해야 하는 이유가 나와 있습니다. 쿼리 창에서 다음 쿼리를 입력하고 각 문을 개별적으로 실행합니다. 

**쿼리 1**에는 마지막 작업이 로그인이었던 계정이 있습니다. 먼저 SecurityEvent 테이블이 요약되고 각 계정에 대한 최신 행이 반환됩니다.  그런 다음 EventID가 4624(로그인)인 행만 반환됩니다.

```KQL
SecurityEvent
| summarize arg_max(TimeGenerated, *) by Account
| where EventID == "4624"
```

**쿼리 2**에는 로그인된 계정의 가장 최근 로그인이 있습니다. SecurityEvent 테이블은 EventID = 4624만 포함하도록 필터링됩니다. 그러면 해당 결과가 계정별로 최신 로그인 행에 대해 요약됩니다.

```KQL
SecurityEvent
| where EventID == "4624"
| summarize arg_max(TimeGenerated, *) by Account
```

**참고:**  "Completed." 막대를 선택하고 두 문 간에 데이터를 비교함으로써 "Total CPU" 및 "Data used for processed query"를 검토할 수도 있습니다.

8. 다음 문에는 make_list 함수 사용법이 나와 있습니다.

make_list 함수는 그룹에 있는 식의 모든 값에 대한 동적(JSON) 배열을 반환합니다. 이 KQL 쿼리는 먼저 where 연산자를 사용하여 EventID를 필터링합니다.  그런 다음 각 컴퓨터에서 결과는 계정의 JSON 배열입니다. 결과 JSON 배열에는 중복된 계정이 포함됩니다.

쿼리 창에서 다음 문을 입력하고 **실행**을 선택합니다. 

```KQL
SecurityEvent
| where EventID == "4624"
| summarize make_list(Account) by Computer
```

9. 다음 문에는 make_set 함수 사용법이 나와 있습니다.

make_set 함수는 식이 그룹으로 가져오는 *개별* 값이 포함된 동적(JSON) 배열을 반환합니다. 이 KQL 쿼리는 먼저 where 연산자를 사용하여 EventID를 필터링합니다.  그런 다음 각 컴퓨터에서 결과는 고유한 계정의 JSON 배열입니다. 쿼리 창에서 다음 문을 입력하고 **실행**을 선택합니다. 


```KQL
SecurityEvent
| where EventID == "4624"
| summarize make_set(Account) by Computer
```

### 작업 4: Render 연산자를 사용하여 KQL에서 시각화 만들기

이 작업에서는 KQL 문을 사용하여 시각화를 생성합니다.

1. 다음 문에는 막대형 차트를 사용하여 결과를 시각화하는 render 함수 사용법이 나와 있습니다. 쿼리 창에서 다음 문을 입력하고 **실행**을 선택합니다. 

```KQL
SecurityEvent 
| summarize count() by Account
| render barchart
```

2. 다음 문에는 시계열을 사용하여 결과를 시각화하는 render 함수 사용법이 나와 있습니다.

bin() 함수는 주어진 bin 크기의 정수 배수로 값을 반내림합니다.  summarize by... 형식과 함께 자주 사용됩니다. 분산된 값 집합이 있는 경우 값이 특정 값의 더 작은 집합으로 그룹화됩니다.  생성된 시계열과 파이프를 시간 차트 형식의 렌더링 연산자로 결합하면 시계열 시각화가 제공됩니다. 쿼리 창에서 다음 문을 입력하고 **실행**을 선택합니다. 

```KQL
SecurityEvent 
| summarize count() by bin(TimeGenerated, 1h) 
| render timechart
```

### 작업 5: KQL에서 다중 테이블 문 작성

이 작업에서는 다중 테이블 KQL 문을 작성합니다.

1. 다음 문에는 테이블 두 개 이상을 가져온 다음 모든 테이블의 행을 반환하는 union 연산자의 사용법이 나와 있습니다. 결과가 파이프 문자에 어떻게 전달되고 영향을 받는지 이해하는 것은 중요합니다. 쿼리 창에서 다음 문을 입력하고 각각에 대해 **실행**을 선택하여 결과를 봅니다. 


**쿼리 1**은 SecurityEvent의 모든 행과 SecurityAlert의 모든 행을 반환합니다.
```KQL
SecurityEvent 
| union SecurityAlert  
```

**쿼리 2**는 SecurityEvent의 모든 행과 SecurityAlert의 모든 행의 수인 행 1개와 열 1개를 반환합니다.
```KQL
SecurityEvent 
| union SecurityAlert  
| summarize count() 
| project count_
```

**쿼리 3**은 SecurityEvent의 모든 행과 SecurityAlert의 하나의 행을 반환합니다.  SecurityAlert의 행에는 SecurityAlert 행의 수가 포함됩니다.
```KQL
SecurityEvent 
| union (SecurityAlert  | summarize count()) 
| project count_
```

2. 다음 문에는 union 연산자가 여러 테이블을 통합하는 와일드카드를 지원하는 방식이 나와 있습니다. 쿼리 창에서 다음 문을 입력하고 **실행**을 선택합니다. 


```KQL
union Security* 
| summarize count() by Type
```


3. 다음 문에는 join 연산자의 사용법이 나와 있습니다. join 연산자는 두 테이블의 행을 병합한 다음 각 테이블에서 지정된 열의 값 일치 여부를 확인하여 새 테이블을 생성합니다. 쿼리 창에서 다음 문을 입력하고 **실행**을 선택합니다. 


```KQL
SecurityEvent 
| where EventID == "4624" 
| summarize LogOnCount=count() by EventID, Account 
| project LogOnCount, Account 
| join kind = inner (
     SecurityEvent 
     | where EventID == "4634" 
     | summarize LogOffCount=count() by EventID, Account 
     | project LogOffCount, Account 
) on Account
```

조인에서 지정된 첫 번째 테이블은 왼쪽 테이블로 간주됩니다.  조인 키워드 뒤의 테이블은 오른쪽 테이블입니다.  테이블의 열로 작업을 할 때는 참조 대상 테이블 열을 구분하기 위해 $left.Column name 이름 및 $right.Column 이름을 사용합니다. 

### 작업 6: KQL에서 문자열 데이터 작업

이 작업에서는 KQL 문을 사용하여 구조화된 문자열 필드 및 구조화되지 않은 문자열 필드 작업을 수행합니다.

1. 다음 문에는 extract 함수 사용법이 나와 있습니다.  텍스트 문자열에서 정규식에 일치하는 항목을 추출합니다. 추출된 하위 문자열을 지정된 형식으로 변환하는 옵션이 있습니다. 쿼리 창에서 다음 문을 입력하고 **실행**을 선택합니다. 

```KQL
print extract("x=([0-9.]+)", 1, "hello x=45.6|wo") == "45.6"
```

2. 다음 문에서는 extract 함수를 사용하여 SecurityEvent 테이블의 Account 필드에서 Account Name을 가져옵니다. 쿼리 창에서 다음 문을 입력하고 **실행**을 선택합니다. 


```KQL
let top5 = SecurityEvent
| where EventID == 4625 and AccountType == 'User'
| extend Account_Name = extract(@"^(.*\\)?([^@]*)(@.*)?$", 2, tolower(Account))
| summarize Attempts = count() by Account_Name
| where Account_Name != ""
| top 5 by Attempts 
| summarize make_list(Account_Name);

SecurityEvent
| where EventID == 4625 and AccountType == 'User'
| extend Name = extract(@"^(.*\\)?([^@]*)(@.*)?$", 2, tolower(Account))
| extend Account_Name = iff(Name in (top5), Name, "Other")
| where Account_Name != ""
| summarize Attempts = count() by Account_Name
```

**참고:** 공백으로 구분된 이 스크립트는 쿼리 창에서 "실행"을 누르기 전에 전체 스크립트가 선택되어 있는지 확인합니다.

3. 다음 문에는 parse 함수 사용법이 나와 있습니다. parse 함수는 문자열 식을 평가하고 해당 값을 계산 열 하나 이상으로 구문 분석합니다. 계산된 열에는 구문 분석에 실패한 문자열에 대한 Null이 포함됩니다.

다음 문을 검토하고 **실행하지는 마세요**. 

```KQL
let SQlData = Event
| where Source has "MSSQL"
;
let Sqlactivity = SQlData
| where RenderedDescription !has "LGIS" and RenderedDescription !has "LGIF"
| parse RenderedDescription with * "action_id:" Action:string 
                                    " " * 
| parse RenderedDescription with * "client_ip:" ClientIP:string
" permission" * 
| parse RenderedDescription with * "session_server_principal_name:" CurrentUser:string
" " * 
| parse RenderedDescription with * "database_name:" DatabaseName:string
"schema_name:" Temp:string
"object_name:" ObjectName:string
"statement:" Statement:string
"." *
;
let FailedLogon = SQlData
| where EventLevelName has "error"
| where RenderedDescription startswith "Login"
| parse kind=regex RenderedDescription with "Login" LogonResult:string
                                            "for user '" CurrentUser:string 
                                            "'. Reason:" Reason:string 
                                            "provided" *
| parse kind=regex RenderedDescription with * "CLIENT" * ":" ClientIP:string 
                                            "]" *
;
let dbfailedLogon = SQlData
| where RenderedDescription has " Failed to open the explicitly specified database" 
| parse kind=regex RenderedDescription with "Login" LogonResult:string
                                            "for user '" CurrentUser:string 
                                            "'. Reason:" Reason:string 
                                            " '" DatabaseName:string
                                            "'" *
| parse kind=regex RenderedDescription with * "CLIENT" * ":" ClientIP:string 
                                            "]" *
;
let successLogon = SQlData
| where RenderedDescription has "LGIS"
| parse RenderedDescription with * "action_id:" Action:string 
                                    " " LogonResult:string 
                                    ":" Temp2:string
                                    "session_server_principal_name:" CurrentUser:string
                                    " " *
| parse RenderedDescription with * "client_ip:" ClientIP:string 
                                    " " *
;
(union isfuzzy=true
Sqlactivity, FailedLogon, dbfailedLogon, successLogon )
| project TimeGenerated, Computer, EventID, Action, ClientIP, LogonResult, CurrentUser, Reason, DatabaseName, ObjectName, Statement
```

4. 다음 문에는 동적 필드 사용법이 나와 있습니다.

Log Analytics 테이블에는 동적으로 정의된 필드 형식이 있습니다.  동적 필드에는 다음과 같은 키-값 쌍이 포함됩니다.
{"eventCategory":"Autoscale","eventName":"GetOperationStatusResult","operationId":"xxxxxxxx-6a53-4aed-bab4-575642a10226","eventProperties":"{\"OldInstancesCount\":6,\"NewInstancesCount\":5}","eventDataId":" xxxxxxxx -efe3-43c2-8c86-cd84f70039d3","eventSubmissionTimestamp":"2020-11-30T04:06:17.0503722Z","resource":"ch-appfevmss-pri","resourceGroup":"CH-RETAILRG-PRI","resourceProviderValue":"MICROSOFT.COMPUTE","subscriptionId":" xxxxxxxx -7fde-4caf-8629-41dc15e3b352","activityStatusValue":"Succeeded"}

동적 필드 내의 문자열에 액세스하기 위해 점 표기법을 사용합니다.  AzureActivity 테이블의 Properties_d 필드는 동적 형식입니다. 해당 예제에서는, eventCategory의 Properties_d.eventCategory 필드 이름에 액세스할 수 있습니다.

쿼리 창에서 다음 문을 입력하고 **실행**을 선택합니다. 

```KQL
AzureActivity
| project Properties_d.eventCategory
```

**참고:** 이 스크립트를 실행하면 결과가 반환되지 않습니다.

다음 문은 검토만 하고 **실행하지는 마세요**. 

```KQL
SigninLogs 
| where TimeGenerated >= ago(1d)
| extend OS = DeviceDetail.operatingSystem, Browser = DeviceDetail.browser
| extend ConditionalAccessPol0Name = tostring(ConditionalAccessPolicies[0].displayName), ConditionalAccessPol0Result = tostring(ConditionalAccessPolicies[0].result)
| extend ConditionalAccessPol1Name = tostring(ConditionalAccessPolicies[1].displayName), ConditionalAccessPol1Result = tostring(ConditionalAccessPolicies[1].result)
| extend ConditionalAccessPol2Name = tostring(ConditionalAccessPolicies[2].displayName), ConditionalAccessPol2Result = tostring(ConditionalAccessPolicies[2].result)
| extend StatusCode = tostring(Status.errorCode), StatusDetails = tostring(Status.additionalDetails)
| extend State = tostring(LocationDetails.state), City = tostring(LocationDetails.city)
| extend Date = startofday(TimeGenerated), Hour = datetime_part("Hour", TimeGenerated)
| summarize count() by Date, Identity, UserDisplayName, UserPrincipalName, IPAddress, ResultType, ResultDescription, StatusCode, StatusDetails, ConditionalAccessPol0Name, ConditionalAccessPol0Result, ConditionalAccessPol1Name, ConditionalAccessPol1Result, ConditionalAccessPol2Name, ConditionalAccessPol2Result, Location, State, City
| sort by Date
```

5. 다음 문에는 문자열 필드에 저장된 JSON을 조작하는 함수가 나와 있습니다. 많은 로그는 JSON 형식으로 데이터를 전송합니다. 해당 경우에는 JSON 데이터를 쿼리 가능한 필드로 변환하는 방법을 알아야 합니다. 

쿼리 창에서 다음 문을 각각 입력하고 **실행**을 선택합니다. 

```KQL
SecurityAlert
| extend ExtendedProperties = todynamic(ExtendedProperties) 
| extend ActionTaken = ExtendedProperties.ActionTaken
| extend AttackerIP = ExtendedProperties["Attacker IP"]
```


```KQL
SecurityAlert
| mv-expand entity = todynamic(Entities)
```


```KQL
SecurityAlert
| where TimeGenerated >= ago(7d)
| mv-apply entity = todynamic(Entities) on 
( where entity.Type == "account" | extend account = strcat (entity.NTDomain, "\\", entity.Name))
```

6. 파서는 Syslog 데이터와 같이 비구조화된 문자열을 사용하여 사전에 구문 분석한 가상 테이블을 정의하는 함수입니다. 다음은 Mailbox 전달 모니터링을 위해 커뮤니티에서 생성된 KQL 쿼리입니다.  

다음 문을 검토하고 **실행하지는 마세요**. 

```KQL
OfficeActivity
    | where TimeGenerated >= ago(30d)
    | where Operation == 'New-InboxRule'
    | extend details = parse_json(Parameters)
    | where details contains 'ForwardTo' or details contains 'RedirectTo'
    | extend ForwardTo = iif(details[0].Name contains 'ForwardTo', details[0].Value,
        iif(details[1].Name contains 'ForwardTo', details[1].Value, 
            iif(details[2].Name contains 'ForwardTo', details[2].Value,  
                iif(details[3].Name contains 'ForwardTo', details[3].Value, 
                    iif(details[4].Name contains 'ForwardTo', details[4].Value,
                        'Check Parameters')))))
    | extend RedirectTo = iif(details[0].Name contains 'RedirectTo', details[0].Value,
        iif(details[1].Name contains 'RedirectTo', details[1].Value,
            iif(details[2].Name contains 'RedirectTo', details[2].Value,
                iif(details[3].Name contains 'RedirectTo', details[3].Value,
                    iif(details[4].Name contains 'RedirectTo', details[4].Value,
                        'Check Parameters')))))
    | extend RuleName = iif(details[3].Name contains 'Name', details[3].Value,
         iif(details[4].Name contains 'Name', details[4].Value,
            iif(details[5].Name contains 'Name', details[5].Value,
                'Check Parameters')))
    | extend RuleParameters = iif(details[2].Name != 'ForwardTo' and  details[2].Name != 'RedirectTo', 
        strcat(tostring(details[2].Name), '-', tostring(details[2].Value)),
        iif(details[3].Name != 'ForwardTo' and  details[3].Name != 'RedirectTo' and details[3].Name != 'Name',
            strcat(tostring(details[3].Name), '-', tostring(details[3].Value)), 
                iff(details[4].Name != 'ForwardTo' and details[4].Name != 'RedirectTo' and details[4].Name != 'Name' and details[4].Name != 'StopProcessingRules',
                strcat(tostring(details[4].Name), '-', tostring(details[4].Value)),
                'All Mail')))
    | project TimeGenerated, Operation, RuleName, RuleParameters, iif(details contains 'ForwardTo', ForwardTo, RedirectTo), ClientIP, UserId
    | project-rename Email_Forwarded_To = Column1, Creating_User = UserId
```

함수를 만들려면

**참고:** 이 랩의 데이터에 사용되는 랩 데모 환경에서는 함수를 만들 수 없습니다. 하지만 함수는 랩 환경에서 사용할 중요한 개념이므로 숙지해 두어야 합니다. 

쿼리를 실행한 후 **저장** 단추를 선택한 다음 이름 (MailboxForward)을 입력한 후 드롭다운에서 **다른 이름으로 저장** 함수를 선택합니다.   

KQL에서 함수 별칭을 통해 함수를 사용할 수 있습니다.

```KQL
MailboxForward
```

## 이 랩을 완료했습니다.

