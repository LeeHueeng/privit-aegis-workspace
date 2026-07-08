# Aegis CLI 사용자 보안 가이드

Aegis CLI는 팀이 소유했거나 테스트 승인을 받은 서비스에 대해 승인된 비파괴 보안 체크를 실행하도록 돕습니다.

## 빠른 시작

```bash
npm install
npm run catalog:generate
npm run aegis -- init
npm run aegis -- scope verify
npm run aegis -- plan --mode passive --target frontend
npm run aegis -- run --target frontend --mode passive
npm run aegis -- report --format html
```

## 승인과 범위

`aegis.scope.json`은 필수입니다. 프로젝트, 환경, 활성 대상, 허용 host/path, 차단 path, 승인 소유자, 증명 방식, 만료일, 안전 제한을 기록합니다. 운영 환경은 기본적으로 passive-only입니다.

## 프론트엔드 이상 캡처

프론트엔드 체크는 헤더, 콘솔 오류, 실패한 네트워크 요약, 스크린샷, DOM 스냅샷 같은 안전한 브라우저/런타임 증거를 수집합니다.

## 백엔드/API 테스트

API 체크는 안전 카탈로그에서 선택됩니다. 인증 및 role matrix 체크는 명시적 승인과 전용 테스트 계정이 필요합니다.

## DB 읽기 전용 감사

데이터베이스 감사 모드는 읽기 전용 구성 검토로 제한됩니다. 쓰기 쿼리, 스키마 변경, 데이터 덤프는 정책으로 차단됩니다.

## 공급망 검사

CI 모드는 SAST, SCA, SBOM, 컨테이너, IaC, secret scanning 연동을 위한 모드입니다.

## Docker 사용

```bash
docker build -t aegis/security-cli .
docker run --rm -v "$PWD:/workspace" aegis/security-cli run --scope aegis.scope.json
```

## npm 사용

패키지는 `security:init`, `security:plan`, `security:frontend`, `security:api`, `security:ci`, `security:report` 스크립트를 포함합니다.

## CI/CD 사용

`aegis scope verify`, `aegis plan --mode ci`, `aegis run --mode ci`를 실행한 뒤 `aegis report --format sarif`로 SARIF를 생성합니다.

## 보고서와 수정

보고서는 범위, 환경, 스캔 구성, 심각도별 finding, artifact, 인증 matrix 자리표시자, 공급망 준비 상태, DB 감사 준비 상태, 수정 가이드를 포함합니다.
