<#
.SYNOPSIS
    [실제 사용 가능] Active Directory 퇴사자 계정 비활성화 스크립트 (Production-Ready)

.DESCRIPTION
    이 스크립트는 퇴사자 발생 시 해당 Active Directory 사용자 계정을 자동으로 비활성화합니다.
    사용자 계정 식별자 (사용자 이름) 를 파라미터로 입력받아 계정을 비활성화합니다.
    오류 처리, 입력 유효성 검사, 로깅 기능을 강화하여 실제 운영 환경에서 안정적으로 사용할 수 있도록 개선되었습니다.

.PARAMETER UserIdentity
    비활성화할 사용자 계정 식별자 (사용자 이름, UserPrincipalName, SID 등) (예: "retireuser" 또는 "retireuser@example.com") - 필수, 실제 사용자 계정 식별자 입력

.EXAMPLE
    .\Disable-ADUser-ProductionReady.ps1 -UserIdentity "retireuser1"

.NOTES
    - 이 스크립트는 Active Directory 모듈이 설치된 환경에서 관리자 권한으로 실행해야 합니다.
    - 실제 운영 환경에서 사용하기 전에 반드시 테스트 환경에서 충분히 테스트하고, IT 관리자 및 보안 담당자와 협의하십시오.
    - 스크립트 실행 로그는 'C:\Logs\ADUserScriptLogs' 폴더에 날짜별 텍스트 파일로 저장됩니다. (로그 경로 사용자 환경에 맞게 변경 가능)
    - 오류 발생 시 자세한 오류 메시지를 화면에 출력하고, 로그 파일에 기록합니다.
    - 입력 파라미터 유효성 검사 기능을 추가하여 잘못된 입력으로 인한 오류를 방지합니다.
    - 계정 비활성화는 되돌릴 수 있지만, 계정 삭제는 신중하게 처리해야 합니다. (이 스크립트는 계정 비활성화만 수행)
    - 스크립트 실행 계정에는 Active Directory 사용자 계정 비활성화에 필요한 최소한의 권한만 부여하십시오.
    - 스크립트 코드를 정기적으로 보안 검토하고, 최신 보안 패치를 적용하십시오.
#>
param (
    [Parameter(Mandatory=$true, HelpMessage="비활성화할 사용자 계정 식별자 (예: 사용자 이름) - 필수, 실제 사용자 계정 식별자 입력")]
    [string]$UserIdentity
)

# 로그 파일 경로 및 파일명 설정 (New-ADUser-ProductionReady.ps크립트와 동일)
$LogFolderPath = "C:\Logs\ADUserScriptLogs"
$LogFileName = Join-Path -Path $LogFolderPath -ChildPath ("Disable-ADUser_{0:yyyyMMdd}.log" -f (Get-Date))

# 로그 폴더 생성 (폴더가 없으면 생성) (New-ADUser-ProductionReady.ps크립트와 동일)
if (!(Test-Path -Path $LogFolderPath -PathType Container)) {
    try {
        New-Item -ItemType Directory -Path $LogFolderPath -Force | Out-Null
    }
    catch {
        Write-Error "로그 폴더 생성 실패: $($_.Exception.Message)"
        return # 로그 폴더 생성 실패 시 스크립트 종료
    }
}

# 로그 기록 함수 (New-ADUser-ProductionReady.ps크립트와 동일)
function Write-LogStart {
    param(
        [string]$Message
    )
    $LogMessage = ("[{0:yyyy-MM-dd HH:mm:ss}] [INFO] Script Start: {1}" -f (Get-Date), $Message)
    Add-Content -Path $LogFileName -Value $LogMessage
    Write-Host $LogMessage -ForegroundColor Green
}

function Write-LogEnd {
    param(
        [string]$Message
    )
    $LogMessage = ("[{0:yyyy-MM-dd HH:mm:ss}] [INFO] Script End: {1}" -f (Get-Date), $Message)
    Add-Content -Path $LogFileName -Value $LogMessage
    Write-Host $LogMessage -ForegroundColor Green
}

function Write-LogInfo {
    param(
        [string]$Message
    )
    $LogMessage = ("[{0:yyyy-MM-dd HH:mm:ss}] [INFO] {0}" -f (Get-Date), $Message)
    Add-Content -Path $LogFileName -Value $LogMessage
    Write-Host $LogMessage -ForegroundColor Gray
}

function Write-LogWarning {
    param(
        [string]$Message
    )
    $LogMessage = ("[{0:yyyy-MM-dd HH:mm:ss}] [WARNING] {0}" -f (Get-Date), $Message)
    Add-Content -Path $LogFileName -Value $LogMessage
    Write-Warning $LogMessage
}

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
        [string]$UserIdentity
    )

    Write-LogInfo "입력 유효성 검사 시작"

    # 사용자 계정 식별자 필수 입력 검사 (문자열 여부만 기본적인 검사)
    if ([string]::IsNullOrEmpty($UserIdentity)) {
        $ErrorMessage = "오류: 사용자 계정 식별자는 필수 입력 항목입니다."
        Write-LogError $ErrorMessage
        throw $ErrorMessage # 스크립트 중단
    }

    Write-LogInfo "입력 유효성 검사 완료"
}


# 메인 스크립트 로직 시작
Write-LogStart "Disable-ADUser 스크립트 시작 - 사용자 계정: '$UserIdentity'"

try {
    # 1. 입력 유효성 검사
    Validate-Input -UserIdentity $UserIdentity
    Write-LogInfo "입력 유효성 검사 통과"

    # 2. Active Directory 사용자 계정 비활성화
    Write-LogInfo "Active Directory 사용자 계정 비활성화 시도 - 사용자 계정: '$UserIdentity'"
    Disable-ADUser -Identity $UserIdentity -ErrorAction Stop

    # 3. 성공 로그 기록 및 메시지 출력
    $SuccessMessage = "사용자 계정 '$UserIdentity'이(가) 성공적으로 비활성화되었습니다."
    Write-LogInfo $SuccessMessage
    Write-Host $SuccessMessage -ForegroundColor Green
}
catch {
    # 오류 발생 시 오류 로그 기록 및 오류 메시지 출력
    Write-LogError "사용자 계정 비활성화 실패 - 사용자 계정: '$UserIdentity', 오류: $($_.Exception.Message)"
    Write-LogError "오류 상세 정보: $($Error[0] | Format-List -Force | Out-String)"
    Write-Error "사용자 계정 비활성화 실패: $($_.Exception.Message)"
}
finally {
    # 스크립트 종료 로그 기록
    Write-LogEnd "Disable-ADUser 스크립트 종료 - 사용자 계정: '$UserIdentity'"
}