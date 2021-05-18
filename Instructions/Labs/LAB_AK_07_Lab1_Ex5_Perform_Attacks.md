# 모듈 7 - 랩 1 - 연습 5 - 공격 수행

### 작업 1: 엔드포인트용 Defender를 사용하여 구성된 Windows 공격

이 작업에서는 엔드포인트용 Microsoft Defender가 구성되어 있는 호스트에서 공격을 수행합니다.

1. WIN1 가상 머신에 Admin으로 로그인합니다. 암호로는 **Pa55w.rd** 를 사용합니다.  

2. 작업 표시줄의 검색 창에 *명령*을 입력합니다.  검색 결과에 명령 프롬프트가 표시됩니다.  명령 프롬프트를 마우스 오른쪽 단추로 클릭하고 **관리자 권한으로 실행**을 선택합니다. 사용자 계정 컨트롤 메시지가 표시되면 실행을 확인합니다.

3. 명령 프롬프트의 각 행에 다음 명령을 입력하고 각 행의 끝에서 Enter 키를 누릅니다.
```
cd \
mkdir temp
cd temp
```
4. 공격 1 - 다음 명령을 복사하여 실행합니다.

```
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "SOC Test" /t REG_SZ /F /D "C:\temp\startup.bat"
```

5. 공격 3 - 다음 명령을 복사하여 실행합니다.

```
notepad c2.ps1
```
**예**를 선택하여 새 파일을 만든 후 아래 PowerShell 스크립트를 c2.ps1에 복사하고 **저장**을 선택합니다.

**참고** 가상 머신에 스크립트를 붙여넣을 때는 길이가 제한될 수 있습니다.  전체 스크립트를 가상 머신에 붙여넣으려면 3개 섹션으로 나눠서 붙여넣으세요.  메모장에서 연 c2.ps1 파일 내에서 스크립트가 여기에 나와 있는 지침과 동일하게 표시되는지 확인합니다.

```


param(
    [string]$Domain = "microsoft.com",
    [string]$Subdomain = "subdomain",
    [string]$Sub2domain = "sub2domain",
    [string]$Sub3domain = "sub3domain",
    [string]$QueryType = "TXT",
        [int]$C2Interval = 8,
        [int]$C2Jitter = 20,
        [int]$RunTime = 240
)


$RunStart = Get-Date
$RunEnd = $RunStart.addminutes($RunTime)

$x2 = 1
$x3 = 1 
Do {
    $TimeNow = Get-Date
    Resolve-DnsName -type $QueryType $Subdomain".$(Get-Random -Minimum 1 -Maximum 999999)."$Domain -QuickTimeout

    if ($x2 -eq 3 )
    {
        Resolve-DnsName -type $QueryType $Sub2domain".$(Get-Random -Minimum 1 -Maximum 999999)."$Domain -QuickTimeout
        
        $x2 = 1

    }
    else
    {
        $x2 = $x2 + 1
    }
    
    if ($x3 -eq 7 )
    {

        Resolve-DnsName -type $QueryType $Sub3domain".$(Get-Random -Minimum 1 -Maximum 999999)."$Domain -QuickTimeout

        $x3 = 1
        
    }
    else
    {
        $x3 = $x3 + 1
    }


    $Jitter = ((Get-Random -Minimum -$C2Jitter -Maximum $C2Jitter) / 100 + 1) +$C2Interval
    Start-Sleep -Seconds $Jitter
}
Until ($TimeNow -ge $RunEnd)

```

명령 프롬프트의 각 행에 다음 명령을 입력하고 각 행의 끝에서 Enter 키를 누릅니다.
```
powershell
.\c2.ps1
```
**참고:** 오류를 해결하라는 메시지가 표시됩니다. 정상적인 현상이므로
이 명령/PowerShell 스크립트를 백그라운드에서 실행하고 창을 닫지 마세요.  명령이 몇 시간 동안 로그 항목을 생성해야 합니다.  이 스크립트가 실행되는 동안 다음 작업과 다음 연습을 진행해도 됩니다.  이 작업에서 생성되는 데이터를 나중에 위협 헌팅 랩에서 사용합니다.  이 프로세스에서 대량의 데이터가 작성되거나 처리되지는 않습니다.

### 작업 2: Sysmon을 사용하여 구성된 Windows 공격

이 작업에서는 보안 이벤트 커넥터와 Sysmon이 구성되어 있는 호스트에서 공격을 수행합니다.

1. WIN2 가상 머신에 Admin으로 로그인합니다. 암호로는 **Pa55w.rd** 를 사용합니다.  

2. 작업 표시줄의 검색 창에 *CMD*를 입력합니다.  검색 결과에 명령 프롬프트가 표시됩니다.  명령 프롬프트를 마우스 오른쪽 단추로 클릭하고 **관리자 권한으로 실행**을 선택합니다.

3. 명령 프롬프트의 각 행에 다음 명령을 입력하고 각 행의 끝에서 Enter 키를 누릅니다.
```
cd \
mkdir temp
cd \temp
```

4. 공격 1 - 다음 명령을 복사하여 실행합니다.

```
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "SOC Test" /t REG_SZ /F /D "C:\temp\startup.bat"
```

5. 공격 2 - 다음 명령을 복사하여 실행합니다. 각 행에 다음 명령을 입력하고 각 행의 끝에서 Enter 키를 누릅니다.

```
net user theusernametoadd /add
net user theusernametoadd ThePassword1!
net localgroup administrators theusernametoadd /add
```

## 연습 6 계속 진행
