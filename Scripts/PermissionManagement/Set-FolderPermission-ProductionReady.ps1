<#
.SYNOPSIS
    [실제 사용 가능] 폴더 또는 파일 공유에 Active Directory 그룹 권한 할당 스크립트 (Production-Ready)

.DESCRIPTION
    이 스크립트는 특정 폴더 또는 파일 공유에 Active Directory 그룹에게 특정 권한 (예: 읽기, 쓰기) 을 자동으로 할당합니다.
    폴더 경로, 그룹 이름, 권한 유형을 파라미터로 입력받아 권한을 설정합니다.
    오류 처리, 입력 유효성 검사, 로깅 기능을 강화하여 실제 운영 환경에서 안정적으로 사용할 수 있도록 개선되었습니다.

.PARAMETER FolderPath
    권한을 설정할 폴더 또는 파일 공유 경로 (예: "\\\\server\\share\\folder" 또는 "C:\data\folder") - 필수, 실제 폴더 경로 입력

.PARAMETER GroupName
    권한을 할당할 Active Directory 그룹 이름 (예: "FileShareUsers") - 필수, 실제 그룹 이름 입력

.PARAMETER Permissions
    할당할 권한 유형 (예: "ReadAndExecute", "Modify", "FullControl") - 필수, ValidateSet 에 정의된 권한 유형 중 하나 선택
    ValidateSet: "ReadAndExecute", "Modify", "FullControl", "Read", "Write", "ListDirectory", "Delete", "TakeOwnership", "ChangePermissions"

.EXAMPLE
    .\Set-FolderPermission-ProductionReady.ps1 -FolderPath "\\\\server\\share\\data" -GroupName "DataReadUsers" -Permissions "ReadAndExecute"

.NOTES
    - 이 스크립트는 Active Directory 모듈이 설치된 환경에서 관리자 권한으로 실행해야 합니다.
    - 실제 운영 환경에서 사용하기 전에 반드시 테스트 환경에서 충분히 테스트하고, IT 관리자 및 보안 담당자와 협의하십시오.
    - 스크립트 실행 로그는 'C:\Logs\ADUserScriptLogs' 폴더에 날짜별 텍스트 파일로 저장됩니다. (로그 경로 사용자 환경에 맞게 변경 가능)
    - 오류 발생 시 자세한 오류 메시지를 화면에 출력하고, 로그 파일에 기록합니다.
    - 입력 파라미터 유효성 검사 기능을 추가하여 잘못된 입력으로 인한 오류를 방지합니다.
    - 권한 유형은 ValidateSet 을 통해 제한됩니다. (System.Security.AccessControl.FileSystemRights 열거형 값 기반)
    - 스크립트 실행 계정에는 폴더/파일 공유 권한 변경에 필요한 최소한의 권한만 부여하십시오.
    - 스크립트 코드를 정기적으로 보안 검토하고, 최신 보안 패치를 적용하십시오.
    - 폴더/파일 공유 경로는 로컬 경로 또는 네트워크 경로 모두 사용할 수 있습니다.
#>
param (
    [Parameter(Mandatory=$true, HelpMessage="권한을 설정할 폴더 또는 파일 공유 경로 - 필수, 실제 폴더 경로 입력")]
    [string]$FolderPath,

    [Parameter(Mandatory=$true, HelpMessage="권한을 할당할 Active Directory 그룹 이름 - 필수, 실제 그룹 이름 입력")]
    [string]$GroupName,

    [Parameter(Mandatory=$true, HelpMessage="할당할 권한 유형 (예: ReadAndExecute, Modify, FullControl) - 필수, ValidateSet 에 정의된 권한 유형 중 하나 선택", ValueFromPipelineByPropertyName=$true)]
    [ValidateSet("ReadAndExecute", "Modify", "FullControl", "Read", "Write", "ListDirectory", "Delete", "TakeOwnership", "ChangePermissions")]
    [string]$Permissions
)

# 로그 파일 경로 및 파일명 설정 (New-ADUser-ProductionReady.ps크립트와 동일)
$LogFolderPath = "C:\Logs\ADUserScriptLogs"
$LogFileName = Join-Path -Path $LogFolderPath -ChildPath ("Set-FolderPermission_{0:yyyyMMdd}.log" -f (Get-Date))

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
        [string]$FolderPath,
        [string]$GroupName,
        [string]$Permissions
    )

    Write-LogInfo "입력 유효성 검사 시작"

    # 폴더 경로 필수 입력 검사 (문자열 여부만 기본적인 검사)
    if ([string]::IsNullOrEmpty($FolderPath)) {
        $ErrorMessage = "오류: 폴더 경로는 필수 입력 항목입니다."
        Write-LogError $ErrorMessage
        throw $ErrorMessage # 스크립트 중단
    }

    # 그룹 이름 필수 입력 검사 (문자열 여부만 기본적인 검사)
    if ([string]::IsNullOrEmpty($GroupName)) {
        $ErrorMessage = "오류: 그룹 이름은 필수 입력 항목입니다."
        Write-LogError $ErrorMessage
        throw $ErrorMessage # 스크립트 중단
    }

    # 권한 유형 필수 입력 및 ValidateSet 검사 (ValidateSet 속성으로 이미 검사되지만, 명시적으로 다시 검사)
    if ([string]::IsNullOrEmpty($Permissions)) {
        $ErrorMessage = "오류: 권한 유형은 필수 입력 항목입니다."
        Write-LogError $ErrorMessage
        throw $ErrorMessage # 스크립트 중단
    }
    if ($Permissions -notin ("ReadAndExecute", "Modify", "FullControl", "Read", "Write", "ListDirectory", "Delete", "TakeOwnership", "ChangePermissions")) {
        $ErrorMessage = "오류: 권한 유형은 ValidateSet 에 정의된 값 중 하나여야 합니다. 입력 값: '$Permissions'"
        Write-LogError $ErrorMessage
        throw $ErrorMessage # 스크립트 중단
    }


    Write-LogInfo "입력 유효성 검사 완료"
}


# 메인 스크립트 로직 시작
Write-LogStart "Set-FolderPermission 스크립트 시작 - 폴더 경로: '$FolderPath', 그룹 이름: '$GroupName', 권한 유형: '$Permissions'"

try {
    # 1. 입력 유효성 검사
    Validate-Input -FolderPath $FolderPath -GroupName $GroupName -Permissions $Permissions
    Write-LogInfo "입력 유효성 검사 통과"

    # 2. 폴더 ACL (Access Control List) 가져오기
    Write-LogInfo "폴더 ACL 가져오기 시도 - 폴더 경로: '$FolderPath'"
    $acl = Get-Acl -Path $FolderPath -ErrorAction Stop

    # 3. FileSystemAccessRule 객체 생성 (그룹, 권한 유형, 상속 유형, 적용 유형 설정)
    Write-LogInfo "FileSystemAccessRule 객체 생성 시도 - 그룹 이름: '$GroupName', 권한 유형: '$Permissions'"
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule `
        ("$GroupName","${Permissions}","ContainerInherit,ObjectInherit","None","Allow")

    # 4. ACL 에 AccessRule 추가
    Write-LogInfo "ACL 에 AccessRule 추가 시도 - 그룹 이름: '$GroupName', 권한 유형: '$Permissions'"
    $acl.AddAccessRule($AccessRule)

    # 5. 변경된 ACL 폴더에 적용
    Write-LogInfo "변경된 ACL 폴더에 적용 시도 - 폴더 경로: '$FolderPath'"
    Set-Acl -Path $FolderPath -AclObject $acl -ErrorAction Stop

    # 6. 성공 로그 기록 및 메시지 출력
    $SuccessMessage = "폴더 '$FolderPath'에 그룹 '$GroupName'에 '$Permissions' 권한이 성공적으로 할당되었습니다."
    Write-LogInfo $SuccessMessage
    Write-Host $SuccessMessage -ForegroundColor Green
}
catch {
    # 오류 발생 시 오류 로그 기록 및 오류 메시지 출력
    Write-LogError "폴더 권한 할당 실패 - 폴더 경로: '$FolderPath', 그룹 이름: '$GroupName', 권한 유형: '$Permissions', 오류: $($_.Exception.Message)"
    Write-LogError "오류 상세 정보: $($Error[0] | Format-List -Force | Out-String)"
    Write-Error "폴더 권한 할당 실패: $($_.Exception.Message)"
}
finally {
    # 스크립트 종료 로그 기록
    Write-LogEnd "Set-FolderPermission 스크립트 종료 - 폴더 경로: '$FolderPath', 그룹 이름: '$GroupName', 권한 유형: '$Permissions'"
}