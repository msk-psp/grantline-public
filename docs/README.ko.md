# Grantline

[English](../README.md) · [한국어](README.ko.md) · [日本語](README.ja.md) · [简体中文](README.zh-CN.md)

**복잡한 권한을 풀고, 부여 경로를 따라가세요.**

**PostgreSQL, ClickHouse, S3 호환 스토리지**의 권한을 한곳에서 확인하고 관리하는
오픈소스 대시보드입니다. SeaweedFS도 지원합니다. 역할 기반 접근 제어(RBAC)를
시각화하고, 역할·그룹·IAM 정책을 따라 접근 경로를 추적하며, 실제 권한과 선언의
차이를 검토할 수 있습니다. 권한 집행은 각 서비스가 담당합니다.

![Grantline 접근 경로 지도](images/routes-map.png)

## 로컬에서 실행하기

Python 3.11 이상과 [uv](https://docs.astral.sh/uv/)가 필요합니다.
데모는 별도 서버나 인증 정보 없이 실행할 수 있습니다.

```bash
git clone https://github.com/msk-psp/grantline-public.git
cd grantline-public
uv venv
uv pip install -e .
source .venv/bin/activate
grantline -c examples/demo/grantline.toml serve
```

**http://127.0.0.1:8420/** 에 접속하세요. 첫 화면은 접근 경로 지도입니다.
**서비스**에서 서비스별 리소스를, **권한 표**에서 권한을 비교하고,
**변경**에서 권한 부여·회수 명령을 미리 확인할 수 있습니다.
계정을 선택하면 해당 계정의 권한과 접근 경로가 표시됩니다.

화면은 **영어·한국어·일본어·중국어 간체**를 지원합니다. 각 페이지 상단에서
언어를 선택하면 쿠키에 저장됩니다. 처음 방문할 때는 브라우저 언어를 사용합니다.
계정명, 리소스 경로, 서비스의 원본 명령어는 그대로 표시됩니다.

## 자주 쓰는 명령

```bash
grantline -c examples/demo/grantline.toml plan      # 권한 차이와 원본 명령 확인
grantline -c examples/demo/grantline.toml apply     # 미리보기만 실행, 변경 없음
grantline -c examples/demo/grantline.toml history  # 기록한 관측 결과 비교
```

`apply --write`는 설정된 시스템을 변경하며, 데모의 데이터 파일도 변경합니다.
실행하기 전에 미리보기와 관리 범위를 확인하세요.

## 실제 시스템 연결하기

실제 설정은 `~/.config/grantline/prod.toml`처럼 저장소 밖에 보관하세요.
설정에는 인증 정보가 담긴 환경 변수의 이름을 지정합니다. 관측용 인증 정보와
쓰기용 인증 정보는 분리합니다. PostgreSQL은
`uv pip install 'grantline[postgres]'`로 추가 의존성을 설치해야 합니다.

아래 상세 문서는 영어로 제공됩니다.

- [설정과 운영](usage.md): 어댑터, 인증 정보, 브리지, 권한 선언, 접근 확인, 관측 기록과 승인.
- [보안](../SECURITY.md): 콘솔 공유와 쓰기 활성화. 내장 서버는 사용자를 인증하지 않으므로 공유 배포에는 인증 프록시가 필요합니다.
- [기여하기](../CONTRIBUTING.md): 개발 환경과 검사 방법.
- [제품 범위](prd/003-scope.md): 요구사항과 구현 현황.

읽지 못한 범위는 **알 수 없음**이며, “접근 권한 없음”으로 처리하지 않습니다.
모든 쓰기는 원본 명령을 먼저 보여주고, 실행 시도와 결과를 감사 기록에 남깁니다.
선언에 따른 권한 회수는 관리 대상으로 지정한 계정과 선언이 다루는 시스템으로 제한됩니다.

## 라이선스

[Apache-2.0](../LICENSE).
