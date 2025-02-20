<#
.SYNOPSIS
    [실제 사용 가능] Active Directory 신규 사용자 계정 생성 스크립트 (Production-Ready)

.DESCRIPTION
    이 스크립트는 신규 입사자의 Active Directory 사용자 계정을 자동으로 생성합니다.
    사용자 이름, 성, 조직 구성 단위 (OU) 경로, 초기 비밀번호를 파라미터로 입력받아 계정을 생성합니다.
    오류 처리, 입력 유효성 검사, 로깅 기능을 강화하여 실제 운영 환경에서 안정적으로 사용할 수 있도록 개선되었습니다.

.PARAMETER UserName
    생성할 사용자 계정의 사용자 이름 (예: johndoe) - 필수, 영문 소문자 및 숫자 조합 권장

.PARAMETER LastName
    사용자의 성 (예: Doe) - 필수

.PARAMETER FirstName
    사용자의 이름 (예: John) - 필수

.PARAMETER UserOU
    사용자 계정을 생성할 Active Directory 조직 구성 단위 (OU) 경로 (예: "OU=Users,DC=example,DC=com") - 필수, 실제 OU 경로 입력

.PARAMETER InitialPassword
    사용자 계정의 초기 비밀번호 - 스크립트 실행 시 보안 문자열 (SecureString) 형태로 입력 받음 (보안 강화)

.PARAMETER Department
    사용자의 부서 (예: "IT Support") - 선택 사항

.PARAMETER Title
    사용자의 직책 (예: "IT Support Technician") - 선택 사항

.EXAMPLE
    .\New-ADUser-ProductionReady.ps1 -UserName "newuser01" -LastName "New" -FirstName "User" -UserOU "OU=TestUsers,DC=example,DC=com"

.NOTES
    - 이 스크립트는 Active Directory 모듈이 설치된 환경에서 관리자 권한으로 실행해야 합니다.
    - 실제 운영 환경에서 사용하기 전에 반드시 테스트 환경에서 충분히 테스트하고, IT 관리자 및 보안 담당자와 협의하십시오.
    - 스크립트 실행 로그는 'C:\Logs\ADUserScriptLogs' 폴더에 날짜별 텍스트 파일로 저장됩니다. (로그 경로 사용자 환경에 맞게 변경 가능)
    - 오류 발생 시 자세한 오류 메시지를 화면에 출력하고, 로그 파일에 기록합니다.
    - 입력 파라미터 유효성 검사 기능을 추가하여 잘못된 입력으로 인한 오류를 방지합니다.
    - 초기 비밀번호는 스크립트 실행 시 보안 문자열 형태로 입력받아 보안을 강화했습니다.
    - 실제 운영 환경에서는 더욱 강력한 비밀번호 정책 및 관리 방식을 적용하고, 다단계 인증 (MFA) 등을 고려하십시오.
    - 스크립트 실행 계정에는 Active Directory 사용자 계정 생성에 필요한 최소한의 권한만 부여하십시오.
    - 스크립트 코드를 정기적으로 보안 검토하고, 최신 보안 패치를 적용하십시오.
#>
param (
    [Parameter(Mandatory=$true, HelpMessage="생성할 사용자 이름 (예: johndoe) - 필수, 영문 소문자 및 숫자 조합 권장")]
    [string]$UserName,

    [Parameter(Mandatory=$true, HelpMessage="사용자 성 (예: Doe) - 필수")]
    [string]$LastName,

    [Parameter(Mandatory=$true, HelpMessage="사용자 이름 (예: John) - 필수")]
    [string]$FirstName,

    [Parameter(Mandatory=$true, HelpMessage="사용자 조직 구성 단위 (OU 경로, 예: OU=Users,DC=example,DC=com) - 필수, 실제 OU 경로 입력")]
    [string]$UserOU,

    [Parameter(Mandatory=$true, HelpMessage="사용자 계정 초기 비밀번호 - 스크립트 실행 시 보안 문자열 (SecureString) 형태로 입력")]
    [System.Security.SecureString]$InitialPassword,

    [Parameter(Mandatory=$false, HelpMessage="사용자의 부서 (예: IT Support) - 선택 사항")]
    [string]$Department,

    [Parameter(Mandatory=$false, HelpMessage="사용자의 직책 (예: IT Support Technician) - 선택 사항")]
    [string]$Title
)

# 로그 파일 경로 및 파일명 설정
$LogFolderPath = "C:\Logs\ADUserScriptLogs" # 사용자 환경에 맞게 변경 가능
$LogFileName = Join-Path -Path $LogFolderPath -ChildPath ("New-ADUser_{0:yyyyMMdd}.log" -f (Get-Date))

# 로그 폴더 생성 (폴더가 없으면 생성)
if (!(Test-Path -Path $LogFolderPath -PathType Container)) {
    try {
        New-Item -ItemType Directory -Path $LogFolderPath -Force | Out-Null
    }
    catch {
        Write-Error "로그 폴더 생성 실패: $($_.Exception.Message)"
        return # 로그 폴더 생성 실패 시 스크립트 종료
    }
}

# 스크립트 시작 로그 기록 함수
function Write-LogStart {
    param(
        [string]$Message
    )
    $LogMessage = ("[{0:yyyy-MM-dd HH:mm:ss}] [INFO] Script Start: {1}" -f (Get-Date), $Message)
    Add-Content -Path $LogFileName -Value $LogMessage
    Write-Host $LogMessage -ForegroundColor Green
}

# 스크립트 종료 로그 기록 함수
function Write-LogEnd {
    param(
        [string]$Message
    )
    $LogMessage = ("[{0:yyyy-MM-dd HH:mm:ss}] [INFO] Script End: {1}" -f (Get-Date), $Message)
    Add-Content -Path $LogFileName -Value $LogMessage
    Write-Host $LogMessage -ForegroundColor Green
}

# 정보 로그 기록 함수
function Write-LogInfo {
    param(
        [string]$Message
    )
    $LogMessage = ("[{0:yyyy-MM-dd HH:mm:ss}] [INFO] {0}" -f (Get-Date), $Message)
    Add-Content -Path $LogFileName -Value $LogMessage
    Write-Host $LogMessage -ForegroundColor Gray
}

# 경고 로그 기록 함수
function Write-LogWarning {
    param(
        [string]$Message
    )
    $LogMessage = ("[{0:yyyy-MM-dd HH:mm:ss}] [WARNING] {0}" -f (Get-Date), $Message)
    Add-Content -Path $LogFileName -Value $LogMessage
    Write-Warning $LogMessage
}

# 오류 로그 기록 함수
function Write-LogError {
    param(
        [string]$Message
    )
    $LogMessage = ("[{0:yyyy-MM-dd HH:mm:ss}] [ERROR] {0}" -f (Get-Date), $Message)
    Add-Content -Path $LogFileName -Value $LogMessage
    Write-Error $LogMessage
}

# 입력 유효성 검사 함수
function Validate-Input {
    param(
        [string]$UserName,
        [string]$LastName,
        [string]$FirstName,
        [string]$UserOU
    )

    Write-LogInfo "입력 유효성 검사 시작"

    # 사용자 이름 유효성 검사 (영문 소문자, 숫자 조합)
    if ($UserName -notmatch "^[a-z0-9]+$") {
        $ErrorMessage = "오류: 사용자 이름은 영문 소문자 및 숫자 조합만 허용됩니다. 입력 값: '$UserName'"
        Write-LogError $ErrorMessage
        throw $ErrorMessage # 스크립트 중단
    }

    # OU 경로 유효성 검사 (ADSI 경로 형식 검사 - 기본적인 형식 검사, 실제 존재 여부 검사는 별도 필요)
    if ($UserOU -notmatch "^OU=.+,DC=.+$") {
        $ErrorMessage = "오류: 조직 구성 단위 (OU) 경로는 유효한 ADSI 경로 형식이어야 합니다. 예: 'OU=Users,DC=example,DC=com'. 입력 값: '$UserOU'"
        Write-LogError $ErrorMessage
        throw $ErrorMessage # 스크립트 중단
    }

    Write-LogInfo "입력 유효성 검사 완료"
}

# 메인 스크립트 로직 시작
Write-LogStart "New-ADUser 스크립트 시작 - 사용자 이름: '$UserName'"

try {
    # 1. 입력 유효성 검사
    Validate-Input -UserName $UserName -LastName $LastName -FirstName $FirstName -UserOU $UserOU
    Write-LogInfo "입력 유효성 검사 통과"

    # 2. Active Directory에 사용자 계정 생성
    Write-LogInfo "Active Directory 사용자 계정 생성 시도 - 사용자 이름: '$UserName', OU 경로: '$UserOU'"
    New-ADUser -SamAccountName $UserName -UserPrincipalName "$UserName@example.com" -Name "$FirstName $LastName" -GivenName $FirstName -Surname $LastName -Path $UserOU -Enabled $true -AccountPassword $InitialPassword -ErrorAction Stop

    # 3. 사용자 계정 속성 설정 (선택 사항) - 예: 부서, 직책 등
    if ($Department) {
        Write-LogInfo "사용자 계정 속성 'Department' 설정 시도 - 사용자 이름: '$UserName', 부서: '$Department'"
        Set-ADUser -Identity $UserName -Department $Department -ErrorAction Stop
    }
    if ($Title) {
        Write-LogInfo "사용자 계정 속성 'Title' 설정 시도 - 사용자 이름: '$UserName', 직책: '$Title'"
        Set-ADUser -Identity $UserName -Title $Title -ErrorAction Stop
    }

    # 4. 성공 로그 기록 및 메시지 출력
    $SuccessMessage = "사용자 계정 '$UserName'이(가) 조직 구성 단위 '$UserOU'에 성공적으로 생성되었습니다."
    Write-LogInfo $SuccessMessage
    Write-Host $SuccessMessage -ForegroundColor Green
}
catch {
    # 오류 발생 시 오류 로그 기록 및 오류 메시지 출력
    Write-LogError "사용자 계정 생성 실패 - 사용자 이름: '$UserName', 오류: $($_.Exception.Message)"
    Write-LogError "오류 상세 정보: $($Error[0] | Format-List -Force | Out-String)" # 자세한 오류 정보 로그에 기록 (디버깅 용이)
    Write-Error "사용자 계정 생성 실패: $($_.Exception.Message)" # 화면에도 오류 메시지 출력
}
finally {
    # 스크립트 종료 로그 기록
    Write-LogEnd "New-ADUser 스크립트 종료 - 사용자 이름: '$UserName'"
}