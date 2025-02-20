<#
.SYNOPSIS
    [실제 사용 가능] Active Directory 사용자 계정 정보 업데이트 스크립트 (Production-Ready)

.DESCRIPTION
    이 스크립트는 기존 Active Directory 사용자 계정의 정보를 업데이트합니다.
    사용자 계정 식별자 (사용자 이름) 와 업데이트할 속성 (부서, 직책, 전화번호) 을 파라미터로 입력받아 계정 정보를 수정합니다.
    오류 처리, 입력 유효성 검사, 로깅 기능을 강화하여 실제 운영 환경에서 안정적으로 사용할 수 있도록 개선되었습니다.

.PARAMETER Identity
    업데이트할 사용자 계정의 식별자 (사용자 이름, UserPrincipalName, SID 등) (예: "johndoe" 또는 "johndoe@example.com") - 필수, 실제 사용자 계정 식별자 입력

.PARAMETER Department
    사용자의 부서 (예: "IT Support") - 선택 사항, 업데이트할 부서 입력

.PARAMETER Title
    사용자의 직책 (예: "IT Support Technician") - 선택 사항, 업데이트할 직책 입력

.PARAMETER OfficePhone
    사용자의 사무실 전화번호 (예: "02-1234-5678") - 선택 사항, 업데이트할 사무실 전화번호 입력

.EXAMPLE
    .\Update-ADUser-ProductionReady.ps1 -Identity "testuser1" -Department "New IT Department" -Title "Senior Test Engineer" -OfficePhone "02-1111-2222"

.NOTES
    - 이 스크립트는 Active Directory 모듈이 설치된 환경에서 관리자 권한으로 실행해야 합니다.
    - 실제 운영 환경에서 사용하기 전에 반드시 테스트 환경에서 충분히 테스트하고, IT 관리자 및 보안 담당자와 협의하십시오.
    - 스크립트 실행 로그는 'C:\Logs\ADUserScriptLogs' 폴더에 날짜별 텍스트 파일로 저장됩니다. (로그 경로 사용자 환경에 맞게 변경 가능)
    - 오류 발생 시 자세한 오류 메시지를 화면에 출력하고, 로그 파일에 기록합니다.
    - 입력 파라미터 유효성 검사 기능을 추가하여 잘못된 입력으로 인한 오류를 방지합니다.
    - 업데이트할 속성이 없는 파라미터는 생략할 수 있습니다.
    - 스크립트 실행 계정에는 Active Directory 사용자 계정 정보 수정에 필요한 최소한의 권한만 부여하십시오.
    - 스크립트 코드를 정기적으로 보안 검토하고, 최신 보안 패치를 적용하십시오.
#>
param (
    [Parameter(Mandatory=$true, HelpMessage="업데이트할 사용자 계정 식별자 (예: 사용자 이름) - 필수, 실제 사용자 계정 식별자 입력")]
    [string]$Identity,

    [Parameter(Mandatory=$false, HelpMessage="사용자 부서 (예: IT Support) - 선택 사항, 업데이트할 부서 입력")]
    [string]$Department,

    [Parameter(Mandatory=$false, HelpMessage="사용자 직책 (예: IT Support Technician) - 선택 사항, 업데이트할 직책 입력")]
    [string]$Title,

    [Parameter(Mandatory=$false, HelpMessage="사용자 사무실 전화번호 (예: 02-1234-5678) - 선택 사항, 업데이트할 사무실 전화번호 입력")]
    [string]$OfficePhone
)

# 로그 파일 경로 및 파일명 설정 (New-ADUser-ProductionReady.ps1 스크립트와 동일)
$LogFolderPath = "C:\Logs\ADUserScriptLogs"
$LogFileName = Join-Path -Path $LogFolderPath -ChildPath ("Update-ADUser_{0:yyyyMMdd}.log" -f (Get-Date))

# 로그 폴더 생성 (폴더가 없으면 생성) (New-ADUser-ProductionReady.ps1 스크립트와 동일)
if (!(Test-Path -Path $LogFolderPath -PathType Container)) {
    try {
        New-Item -ItemType Directory -Path $LogFolderPath -Force | Out-Null
    }
    catch {
        Write-Error "로그 폴더 생성 실패: $($_.Exception.Message)"
        return # 로그 폴더 생성 실패 시 스크립트 종료
    }
}

# 로그 기록 함수 (New-ADUser-ProductionReady.ps1 스크립트와 동일)
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
        [string]$Identity
    )

    Write-LogInfo "입력 유효성 검사 시작"

    # 사용자 계정 식별자 (Identity) 필수 입력 검사 (문자열 여부만 기본적인 검사)
    if (-not [string]::IsNullOrEmpty($Identity)) {
        # 추가적인 사용자 계정 식별자 형식 검사 (예: UPN 형식, SamAccountName 형식 등) 필요 시 추가
    } else {
        $ErrorMessage = "오류: 사용자 계정 식별자 (Identity) 는 필수 입력 항목입니다."
        Write-LogError $ErrorMessage
        throw $ErrorMessage # 스크립트 중단
    }

    Write-LogInfo "입력 유효성 검사 완료"
}


# 메인 스크립트 로직 시작
Write-LogStart "Update-ADUser 스크립트 시작 - 사용자 계정: '$Identity'"

try {
    # 1. 입력 유효성 검사
    Validate-Input -Identity $Identity
    Write-LogInfo "입력 유효성 검사 통과"

    # 2. Active Directory 사용자 계정 정보 업데이트
    Write-LogInfo "Active Directory 사용자 계정 정보 업데이트 시도 - 사용자 계정: '$Identity'"
    Set-ADUser -Identity $Identity `
        -Department $Department `
        -Title $Title `
        -OfficePhone $OfficePhone -ErrorAction Stop

    # 3. 성공 로그 기록 및 메시지 출력
    $SuccessMessage = "사용자 계정 '$Identity' 정보가 성공적으로 업데이트되었습니다."
    Write-LogInfo $SuccessMessage
    Write-Host $SuccessMessage -ForegroundColor Green

}
catch {
    # 오류 발생 시 오류 로그 기록 및 오류 메시지 출력
    Write-LogError "사용자 계정 정보 업데이트 실패 - 사용자 계정: '$Identity', 오류: $($_.Exception.Message)"
    Write-LogError "오류 상세 정보: $($Error[0] | Format-List -Force | Out-String)"
    Write-Error "사용자 계정 정보 업데이트 실패: $($_.Exception.Message)"
}
finally {
    # 스크립트 종료 로그 기록
    Write-LogEnd "Update-ADUser 스크립트 종료 - 사용자 계정: '$Identity'"
}