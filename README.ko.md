# Privit Aegis Workspace

[English](./README.md) · [한국어](./README.ko.md) · [日本語](./README.ja.md) · [中文](./README.zh-CN.md) · [GitHub Pages](https://leehueeng.github.io/privit-aegis-workspace/)

Privit Aegis Workspace는 Privit 웹 앱을 위한 승인 기반 보안 테스트
워크스페이스입니다. Aegis CLI, 로컬 웹 콘솔, 패시브 사이트맵 탐색,
보안 헤더/쿠키/폼/API 점검, 다국어 보고서, AI 보조 프롬프트, AIGate
푸시 품질 게이트를 한 레포에서 다룹니다.

## 별을 받을 만한 포인트

- 웹 콘솔과 CLI가 같은 보안 기준을 사용합니다.
- 한국어, 영어, 일본어, 중국어 README와 가이드가 함께 제공됩니다.
- 보고서에는 어떤 검사를 했는지, 통과 기준이 무엇인지, 어떤 증거가
  남았는지가 정리됩니다.
- AI는 검사 결과를 임의로 판단하지 않고 설정, 준비 상태, 개선 프롬프트
  생성에만 보조적으로 사용됩니다.
- GitHub Actions는 최소 권한과 고정된 액션 버전을 기준으로 구성됩니다.

## 빠른 시작

```sh
npm run setup
npm run web
```

브라우저에서 `http://127.0.0.1:4317`을 열면 범위 설정, 검사 실행,
최신 HTML 보고서 확인을 한 번에 할 수 있습니다.

## 주요 검사

- 승인된 범위와 패시브 모드 확인
- 라우트, 링크, 폼, 로그인 후보, 사이트맵 탐색
- CSP, HSTS, Referrer-Policy, X-Content-Type-Options 등 보안 헤더 점검
- 인증 페이지 캐시, 쿠키 플래그, CSRF 후보, GET 로그인 폼 점검
- OpenAPI, GraphQL, OIDC, JWKS, CORS, CSP 품질, SRI, mixed content 점검
- 민감 파일, 소스맵, 디버그/관리자 경로, 공개 API 표면 검토
- 보안침투검사 리포트 생성

기본 검사는 폼 제출, 무차별 대입, 파괴적 페이로드를 실행하지 않습니다.

## 품질 게이트

```sh
npm run site:check
npm run security:audit
npm run security:hardening
npm run ci:aegis
npm run gate:ready
```

AIGate는 깃 푸시와 CI 품질 게이트용입니다. 웹 콘솔은 Aegis 검사와
보고서 흐름에 집중합니다.

## AI 사용 위치

AI는 제공자 설정, 모델 명령어 확인, 실행 환경 진단, 개선 프롬프트,
선택적 AIGate AI 리포트에 사용됩니다. 실제 탐지 결과는 범위, 응답
메타데이터, 헤더, 쿠키, 저위험 패시브 프로브를 기반으로 결정됩니다.

## 문서

- 공개 설명 사이트: <https://leehueeng.github.io/privit-aegis-workspace/>
- 보안 검사 설명: [`docs/security-scanning.md`](./docs/security-scanning.md)
- 다국어 문서 인덱스: [`docs/LANGUAGES.md`](./docs/LANGUAGES.md)
- 로드맵: [`docs/ROADMAP.md`](./docs/ROADMAP.md)
