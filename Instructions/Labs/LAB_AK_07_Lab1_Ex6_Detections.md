# ��� 7 - �� 1 - ���� 6 - �˻� �����

### �۾� 1: Sysmon�� ����Ͽ� ���� 1 �˻�

�� �۾������� ���� �̺�Ʈ Ŀ���Ϳ� Sysmon�� ��ġ�� ȣ��Ʈ���� ���� 1 �˻��� ����ϴ�.

�� ������ ���� �ÿ� ����Ǵ� ������Ʈ�� Ű�� ����ϴ�.  
```Command
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "SOC Test" /t REG_SZ /F /D "C:\temp\startup.bat"
```

1. WIN1 ���� �ӽſ� Admin���� �α����մϴ�. ��ȣ�δ� **Pa55w.rd**�� ����մϴ�.  

2. Edge ���������� Azure Portal https://portal.azure.com���� �̵��մϴ�.

3. �� ȣ���� �����ڰ� ������ �����ڿ� **�׳�Ʈ ���� ����** ������ �����Ͽ� **�α���** ��ȭ ���ڿ� �ٿ����� �� **����**�� �����մϴ�.

4. �� ȣ���� �����ڰ� ������ �����ڿ� **�׳�Ʈ ��ȣ**�� �����Ͽ� **��ȣ �Է�** ��ȭ ���ڿ� �ٿ����� �� **�α���**�� �����մϴ�.

5. Azure Portal�� �˻� â�� *Sentinel*�� �Է��ϰ� **Azure Sentinel**�� �����մϴ�.

6. �տ��� ���� Azure Sentinel �۾� ������ �����մϴ�.

7. �Ϲ� ���ǿ��� **�α�**�� �����մϴ�.

8. ���� �����Ͱ� ����Ǵ� ��ġ�� Ȯ���ؾ� �մϴ�. ��� ������ ���������Ƿ�,  �α� �ð� ������ **���� 24�ð�**���� �����մϴ�.

9. ���� KQL ���� �����մϴ�.

```KQL
search "temp\\startup.bat"
```

10. ������� ������ 3�� ���̺��� ǥ�õ˴ϴ�.
    - DeviceProcessEvents
    - DeviceRegistryEvents
    - Event

    *Device* ���̺��� ��������Ʈ�� Defender(������ Ŀ���� - Microsoft 365 Defender)���� ������ ���Դϴ�.  �׸��� *Event* ���̺��� ���⼭ ����ϴ� ������ Ŀ���� ���� �̺�Ʈ���� ������ ���Դϴ�. 

    ���⼭�� Sysmon�� ��������Ʈ�� Defender�� �� �������� �����͸� �����ϹǷ�, ���߿� ������ �� �ִ� KQL �� �� ���� �ۼ��ؾ� �մϴ�.  �ʱ� ���翡�� �� ���� ���������� ���캼 �����Դϴ�.

    **����:** �幰�� ������ �ε� ���μ��� �ð��� ��Һ��� �� ���� �ɸ��� ��쵵 ���� �� �ֽ��ϴ�.  �׷� ��� �� �ð� ���� ���̺��� ������ ǥ�õ��� ���� �� �ֽ��ϴ�.

11. ù ��° ������ ������ Windows ȣ��Ʈ�� Sysmon�Դϴ�.  ���� KQL ���� �����մϴ�.

```KQL
search in (Event) "temp\\startup.bat"
```
���� ������� Event ���̺� ǥ�õ˴ϴ�.  

12. ���� Ȯ���Ͽ� ���ڵ�� ���õ� ��� ���� ǥ���մϴ�.  EventData, ParameterXml ���� �Ϻ� �ʵ忡�� ���� ������ �׸��� ����ȭ�� �����ͷ� ����Ǿ� �ֽ��ϴ�.  �׷��Ƿ� Ư�� �ʵ带 �����ϱⰡ ��ƽ��ϴ�.  

13. ���� �������δ� �ǹ� �ִ� �ʵ带 ã�� �� �ֵ��� �� ���� �����͸� ���� �м��ϴ� KQL ���� �ۼ��ؾ� �մϴ�.  GitHub�� Azure Sentinel Ŀ�´�Ƽ �� Parsers �������� �پ��� �ļ� ������ ���ԵǾ� �ֽ��ϴ�.  ���������� �ٸ� ���� ���� https://github.com/Azure/Azure-Sentinel�� �̵��մϴ�.

14. **Parsers** ������ **Sysmon** ������ ���ʷ� �����մϴ�.  �׷��� ���� ������ ǥ�õ˴ϴ�. Azure-Sentinel/Parsers/Sysmon/Sysmon-v12.0.txt

15. Sysmon-v12.0.txt ������ �����Ͽ� ǥ���մϴ�.

���� �� ���� Event ���̺��� �����Ͽ� EventData ������ �����ϴ� let ���� �ֽ��ϴ�.


```KQL
let EventData = Event
| where Source == "Microsoft-Windows-Sysmon"
| extend RenderedDescription = tostring(split(RenderedDescription, ":")[0])
| project TimeGenerated, Source, EventID, Computer, UserName, EventData, RenderedDescription
| extend EvData = parse_xml(EventData)
| extend EventDetail = EvData.DataItem.EventData.Data
| project-away EventData, EvData  ;
```

���� �Ʒ��ʿ��� EventData ������ �Է����� ����Ͽ� EventID == 13�� ã�� �� �ٸ� let ���� �ֽ��ϴ�.  

```KQL
let SYSMON_REG_SETVALUE_13=()
{
    let processEvents = EventData
    | where EventID == 13
    | extend RuleName = EventDetail.[0].["#text"], EventType = EventDetail.[1].["#text"], UtcTime = EventDetail.[2].["#text"], ProcessGuid = EventDetail.[3].["#text"], 
    ProcessId = EventDetail.[4].["#text"], Image = EventDetail.[5].["#text"], TargetObject = EventDetail.[6].["#text"], Details = EventDetail.[7].["#text"]
    | project-away EventDetail  ;
    processEvents;
    
};
```
�� ������ �����Ͽ� KQL ���� �ۼ��� �� �ֽ��ϴ�.

16. ���⼭�� ���� ���� ����Ͽ� ��� Registry Key Set Value ���� ǥ���ϴ� KQL ���� ���� �ۼ��մϴ�.  ���� KQL ������ �����մϴ�.

```KQL

Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 13
| extend RenderedDescription = tostring(split(RenderedDescription, ":")[0])
| project TimeGenerated, Source, EventID, Computer, UserName, EventData, RenderedDescription
| extend EvData = parse_xml(EventData)
| extend EventDetail = EvData.DataItem.EventData.Data
| project-away EventData, EvData  
| extend RuleName = EventDetail.[0].["#text"], EventType = EventDetail.[1].["#text"], UtcTime = EventDetail.[2].["#text"], ProcessGuid = EventDetail.[3].["#text"], 
    ProcessId = EventDetail.[4].["#text"], Image = EventDetail.[5].["#text"], TargetObject = EventDetail.[6].["#text"], Details = EventDetail.[7].["#text"]
    | project-away EventDetail 


```

   ![��ũ����](../Media/SC200_sysmon_query1.png)

17.  �˻� ��Ģ�� ��� �ۼ��� ���� ������, �� KQL ���� �ٸ� �˻� ��Ģ�� KQL ���� �� KQL ���� ������ �� ���� ������ ���Դϴ�.  �α� â���� **����**, **�Լ��� ����**�� ���ʷ� �����մϴ�. ���� �ö��̾ƿ����� ������ �Է��ϰ� �Լ��� �����մϴ�.

�Լ� �̸�: Event_Reg_SetValue
����: Sysmon


18. �� �α� ���� ���� ���ϴ�. �ش� �ǿ��� ���� KQL ���� �����մϴ�.

```KQL

Event_Reg_SetValue

```
���� ������ �÷��ǿ� ���� ���� ���� �� ��ȯ�� ���� �ֽ��ϴ�.  �������� �����̹Ƿ� �����ϼ���.  ���� �۾����� �� ���� �ó������� �°� ����� ���͸��մϴ�.

19. ���� KQL ���� �����մϴ�.

```KQL

Event_Reg_SetValue | search "startup.bat"

```
�׷��� �ʿ��� ���ڵ尡 ��ȯ�˴ϴ�. ���� �ش� ���ڵ��� �����͸� �����Ͽ� �� �ĺ��� ���� ���� ������ �κ��� Ȯ���� �� �ֽ��ϴ�.

20. �� ������ ���� ���ڸ����������� ���� �����ڰ� reg.exe�� ����Ͽ� ������Ʈ�� Ű�� �߰��Ѵٴ� ���� Ȯ�εǾ����ϴ�.  ������Ʈ�� Ű�� �߰��� ���͸��� c:\temp�Դϴ�. startup.bat�� �ٸ� �̸��� ���� �ֽ��ϴ�. ���� ��ũ��Ʈ�� �����մϴ�.

```KQL
Event_Reg_SetValue 
| where Image contains "reg.exe"

```
���� �ĺ��� ������ �����Ǿ����ϴ�.  �������δ� c:\temp������ ����� ��ȯ�ǵ��� �����ؾ� �մϴ�.

21. ���� ���� KQL ���� �����մϴ�.

```KQL
Event_Reg_SetValue 
| where Image contains "reg.exe"
| where Details startswith "C:\\TEMP"
```

���� ������ �˻� ��Ģ�� �ۼ��Ǿ����ϴ�.  

22. ���� � �м��ڰ� ������ ��Ȯ�ϰ� �м��� �� �ֵ��� ��� ���� ��Ȳ ������ �ִ��� ���� �����ؾ� �մϴ�. ���� ���� �׷����� ����� ����Ƽ ���� ������ �� �ֽ��ϴ�.  ���� ������ �����մϴ�.

```KQL
Event_Reg_SetValue 
| where Image contains "reg.exe"
| where Details startswith "C:\\TEMP"
| extend timestamp = TimeGenerated, HostCustomEntity = Computer, AccountCustomEntity = UserName

```

23. ���� ������ �˻� ��Ģ�� �ۼ��Ǿ����Ƿ� ������ �ִ� �α� â�� ��� �������� **+ �� ��� ��Ģ**�� �����ϰ� **Azure Sentinel ��� �����**�� �����մϴ�.

24. �׷��� �м� ��Ģ �����簡 ���۵˴ϴ�.  �Ϲ� �ǿ��� ���� ������ �Է��մϴ�.

    �̸�: Sysmon Startup RegKey

    ����: c:\temp�� Sysmon Startup RegKey

    ����: ���Ӽ�

    �ɰ���: ����

**����: ��Ģ �� ���� >** �� �����մϴ�.

25. **��Ģ �� ����** �ǿ��� **��Ģ ����**���� ������ �̹� �ԷµǾ� �ֽ��ϴ�.

26. ���� ���࿡�� ���� �׸��� �����մϴ�.

- ���� ���� ����: 5��
- �����͸� Ȯ���� �Ⱓ: 1��

**����** ���⼭�� ���� �����Ϳ� ���� �ǵ������� ���� �νô�Ʈ�� �����մϴ�.  �׷��� ������ �ش� ��� ����� �� �ֱ� �����Դϴ�.

27. ������ �ɼ��� �⺻������ �Ӵϴ�.  **����: �νô�Ʈ ���� >** ���߸� Ŭ���մϴ�.

28. �νô�Ʈ �������� ���� �׸��� �����մϴ�. 

- �νô�Ʈ ����: ���
- ��� �׷�: ��� �� ��

**����: �ڵ�ȭ�� ���� >** ���߸� Ŭ���մϴ�.

29. �ڵ�ȭ�� ���� �ǿ��� ���� �׸��� �����մϴ�.

- *PostMessageTeams-OnAlert*�� �����մϴ�.

**����: ����** ���߸� �����մϴ�.

30. ���� �ǿ��� **�����** ���߸� �����մϴ�.


### �۾� 2: ��������Ʈ�� Defender�� ����Ͽ� ���� 1 �˻�

�� �۾������� ��������Ʈ�� Defender�� �����Ǿ� �ִ� ȣ��Ʈ���� ���� 1 �˻��� ����ϴ�.

�� ������ ���� �ÿ� ����Ǵ� ������Ʈ�� Ű�� ����ϴ�.  
```Command
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "SOC Test" /t REG_SZ /F /D "C:\temp\startup.bat"
```

1. Azure Sentinel ������ �Ϲ� ���ǿ��� **�α�**�� �����մϴ�.

2. ���� �����Ͱ� ����Ǵ� ��ġ�� Ȯ���ؾ� �մϴ�. ��� ������ ���������Ƿ�,  

    �α� �ð� ������ ���� 24�ð����� �����մϴ�.

3. ���� KQL ���� �����մϴ�.

```KQL
search "temp\\startup.bat"
```

4. ������� ������ 3�� ���̺��� ǥ�õ˴ϴ�.
    DeviceProcessEvents
    DeviceRegistryEvents
    Event

    Device* ���̺��� ��������Ʈ�� Defender(������ Ŀ���� - Microsoft 365 Defender)���� ������ ���Դϴ�.  �׸��� Event ���̺��� ���⼭ ����ϴ� ������ Ŀ���� ���� �̺�Ʈ���� ������ ���Դϴ�. 

    ���⼭�� Sysmon�� ��������Ʈ�� Defender�� �� �������� �����͸� �����ϹǷ�,  ���߿� ������ �� �ִ� KQL �� �� ���� �ۼ��ؾ� �մϴ�.  �ʱ� ���翡�� �� ���� ���������� ���캼 �����Դϴ�.

5. �� �˻������� ��������Ʈ�� Defender�� �����͸� ���������� ã���ϴ�.  ���� KQL ���� �����մϴ�.

```KQL
search in (Device*) "temp\\startup.bat"
```

6. �̹� �Ϲ�ȭ�Ǿ� ���� ������ �� �ִ� �����ʹ� DeviceRegistryEvents ���̺� ���ԵǾ� �ִ� ������ ���Դϴ�.  ���� Ȯ���Ͽ� ���ڵ�� ���õ� ��� ���� ǥ���մϴ�.

7. �� ������ ���� ���ڸ����������� ���� �����ڰ� reg.exe�� ����Ͽ� ������Ʈ�� Ű�� �߰��Ѵٴ� ���� Ȯ�εǾ����ϴ�.  ������Ʈ�� Ű�� �߰��� ���͸��� c:\temp�Դϴ�. startup.bat�� �ٸ� �̸��� ���� �ֽ��ϴ�.  ���� KQL ���� �Է��մϴ�.

```KQL

DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where InitiatingProcessFileName == "reg.exe"
| where RegistryValueData startswith "c:\\temp"


```

���� ������ �˻� ��Ģ�� �ۼ��Ǿ����ϴ�.  

8. ���� � ���� �м��ڰ� ������ ��Ȯ�ϰ� �м��� �� �ֵ��� ��� ���� ��Ȳ ������ �ִ��� ���� �����ؾ� �մϴ�. ���� ���� �׷����� ����� ����Ƽ ���� ������ �� �ֽ��ϴ�. ���� ������ �����մϴ�.

```KQL
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where InitiatingProcessFileName == "reg.exe"
| where RegistryValueData startswith "c:\\temp"
| extend timestamp = TimeGenerated, HostCustomEntity = DeviceName, AccountCustomEntity = InitiatingProcessAccountName


```

   ![��ũ����](../Media/SC200_sysmon_query2.png)

9.  ���� ������ �˻� ��Ģ�� �ۼ��Ǿ����Ƿ� ������ �ִ� �α� â�� ��� �������� **+ �� ��� ��Ģ**�� �����մϴ�.  **Azure Sentinel ��� �����**�� �����մϴ�.

10. �׷��� �м� ��Ģ �����簡 ���۵˴ϴ�.  �Ϲ� �ǿ��� ���� ������ �Է��մϴ�.


    �̸�: D4E Startup RegKey

    ����: c:\temp�� D4E Startup Regkey

    ����: ���Ӽ�

    �ɰ���: ����

11. **����: ��Ģ �� ���� >** ���߸� �����մϴ�.

12. ��Ģ �� ���� �ǿ��� **��Ģ ����**���� ������ �̹� �ԷµǾ� �ֽ��ϴ�.

13. ���� ���࿡�� ���� �׸��� �����մϴ�.

- ���� ���� ����: 5��
- �����͸� Ȯ���� �Ⱓ: 1��

**����** ���⼭�� ���� �����Ϳ� ���� �ǵ������� ���� �νô�Ʈ�� �����մϴ�.  �׷��� ������ �ش� ��� ����� �� �ֱ� �����Դϴ�.

14. ������ �ɼ��� �⺻������ �Ӵϴ�.  **����: �νô�Ʈ ����**�� �����ϰ�

15. �νô�Ʈ �������� ���� �׸��� �����մϴ�. 

- �νô�Ʈ ����: ���
- ��� �׷�: ��� �� ��

**����: �ڵ�ȭ�� ���� >** �� �����ϰ�

16. �ڵ�ȭ�� ���� �ǿ��� ���� �׸��� �����մϴ�.

- PostMessageTeams-OnAlert�� �����մϴ�.
- **����: ����**�� �����մϴ�.

17. ���� �� ����� �ǿ��� **�����**�� �����մϴ�.

### �۾� 3: SecurityEvent�� ����Ͽ� ���� 2 �˻�

�� �۾������� ���� �̺�Ʈ Ŀ���Ϳ� Sysmon�� ��ġ�� ȣ��Ʈ���� ���� 2 �˻��� ����ϴ�.

�� ������ �� ����ڸ� ����� ���� �����ڿ� �߰��մϴ�.
```Command
net user theusernametoadd /add
net user theusernametoadd ThePassword1!
net localgroup administrators theusernametoadd /add
```

1. Azure Sentinel ������ �Ϲ� ���ǿ��� **�α�**�� �����մϴ�.

2. ���� �����Ͱ� ����Ǵ� ��ġ�� Ȯ���ؾ� �մϴ�. ��� ������ ���������Ƿ�,  

    �α� �ð� ������ ���� 24�ð����� �����մϴ�.

3. ���� KQL ���� �����մϴ�.

```KQL
search "administrators"
```

4. ������� ���� ���̺��� ǥ�õ˴ϴ�.
    Event
    SecurityEvent

5. ù ��° ������ ������ SecurityEvent�Դϴ�. Windows���� ���� �ִ� �׷쿡 �������� �߰��ϴ� �۾��� �ĺ��ϴ� �� ����ϴ� �̺�Ʈ ID�� �����ؾ� �մϴ�.  ���⼭ �ش� ������ ���� EventID �� Event�Դϴ�.

4732 - �������� ���ȵ� ���� �׷쿡 �߰��߽��ϴ�.

���� ��ũ��Ʈ�� �����մϴ�.

```KQL
SecurityEvent
| where EventID == "4732"
| where TargetAccount == "Builtin\\Administrators"

```

6. ���� Ȯ���Ͽ� ���ڵ�� ���õ� ��� ���� ǥ���մϴ�.  �׷��� ã������ ����� �̸��� ǥ�õ��� �ʽ��ϴ�.  ����� �̸��� ����Ǵ� ��� SID(���� �ĺ���)�� ����Ǳ� �����Դϴ�.  ���� KQL�� SID ��ġ ���θ� Ȯ���Ͽ� Administrators �׷쿡 �߰��� TargetUserName�� ���� �Է��մϴ�.


```KQL
SecurityEvent
| where EventID == "4732"
| where TargetAccount == "Builtin\\Administrators"
| extend Acct = MemberSid, MachId = SourceComputerId 
| join kind=leftouter (
     SecurityEvent 
     | summarize count() by TargetSid, SourceComputerId, TargetUserName
     | project Acct1 = TargetSid, MachId1 = SourceComputerId, UserName1 = TargetUserName
) on $left.MachId == $right.MachId1, $left.Acct == $right.Acct1 

```
���� ������ �˻� ��Ģ�� �ۼ��Ǿ����ϴ�.  

   ![��ũ����](../Media/SC200_sysmon_attack3.png)

**����:** �������� ���Ǵ� ������ ��Ʈ�� �۾Ƽ� �� KQL�� ������ ����� ��ȯ���� ���� ���� �ֽ��ϴ�.

7. ���� � �м��ڰ� ������ ��Ȯ�ϰ� �м��� �� �ֵ��� ��� ���� ��Ȳ ������ �ִ��� ���� �����ؾ� �մϴ�. ���� ���� �׷����� ����� ����Ƽ ���� ������ �� �ֽ��ϴ�.  ���� ������ �����մϴ�.


```KQL
SecurityEvent
| where EventID == "4732"
| where TargetAccount == "Builtin\\Administrators"
| extend Acct = MemberSid, MachId = SourceComputerId 
| join kind=leftouter (
     SecurityEvent 
     | summarize count() by TargetSid, SourceComputerId, TargetUserName
     | project Acct1 = TargetSid, MachId1 = SourceComputerId, UserName1 = TargetUserName
) on $left.MachId == $right.MachId1, $left.Acct == $right.Acct1 
| extend timestamp = TimeGenerated, HostCustomEntity = Computer, AccountCustomEntity = UserName1

```

8. ���� ������ �˻� ��Ģ�� �ۼ��Ǿ����Ƿ� ������ �ִ� �α� â�� ��� �������� **+ �� ��� ��Ģ**�� �����ϰ� **Azure Sentinel ��� �����**�� �����մϴ�.

9. �׷��� �м� ��Ģ �����簡 ���۵˴ϴ�.  �Ϲ� �ǿ��� ���� ������ �Է��մϴ�.

- �̸�: SecurityEvents Local Administrators User Add 
- ����: SecurityEvents Local Administrators User Add 
- ����: ���� �����÷��̼�
- �ɰ���: ����

**����: ��Ģ �� ���� >** ���߸� �����մϴ�.

10. ��Ģ �� ���� ���� ��Ģ ���� �� ����Ƽ ���ο��� ������ �̹� �ԷµǾ� �ֽ��ϴ�.

11. ���� ���࿡�� ���� �׸��� �����մϴ�.

- ���� ���� ����: 5��
- �����͸� Ȯ���� �Ⱓ: 1��

**����** ���⼭�� ���� �����Ϳ� ���� �ǵ������� ���� �νô�Ʈ�� �����մϴ�.  �׷��� ������ �ش� ��� ����� �� �ֱ� �����Դϴ�.

12. ������ �ɼ��� �⺻������ �Ӵϴ�.  **����: �νô�Ʈ ����**�� �����ϰ�

13. �νô�Ʈ �������� ���� �׸��� �����մϴ�.

- �νô�Ʈ ����: ���
- ��� �׷�: ��� �� ��
- **����: �ڵ�ȭ�� ���� >�� �����ϰ�**

14. �ڵ�ȭ�� ���� �ǿ��� ���� �׸��� �����մϴ�.

- **PostMessageTeams-OnAlert**�� �����մϴ�.
- **����: ���� >** ���߸� �����մϴ�.

15. ���� �ǿ��� **�����**�� �����մϴ�.

## ���� 7 ��� ����
