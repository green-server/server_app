# greenserver

Green Server의 서버용 에이전트입니다. 전력 지표를 백엔드로 보내고, 요청이 오면 이 서버에서 Claude Code를 실행해 전력 낭비를 진단하고 조치합니다. 연결은 서버에서 바깥으로만 나가고 포트를 열지 않습니다.

## 설치

Linux와 systemd가 필요합니다. 토큰은 웹에서 서버를 등록할 때 한 번만 표시됩니다.

```sh
curl -fsSL https://raw.githubusercontent.com/green-server/server_app/main/install.sh \
  | sudo GREENSERVER_TOKEN=<토큰> bash -s -- --server wss://<백엔드>/ws/agent --services nginx,minecraft
```

| 옵션 | 설명 |
|---|---|
| `--server URL` | 백엔드 주소. 필수 |
| `--services a,b` | AI가 승인을 받아 중지, 시작, 재시작할 수 있는 서비스. 생략하면 없음 |
| `--idle-watts N`, `--max-watts N` | RAPL이 없을 때 쓰는 전력 프로필 |
| `--binary PATH` | 릴리스를 내려받지 않고 이 파일을 설치 |

설치 스크립트는 전용 계정 `greenserver`, 바이너리, systemd 유닛, sudoers 화이트리스트, RAPL 읽기 권한을 준비합니다. AI 컨설팅을 쓰려면 이 계정에 Claude Code를 설치한 뒤 인증합니다.

- 구독: `sudo -u greenserver -H claude /login`
- API 키: `/etc/greenserver/env`에 `ANTHROPIC_API_KEY=...`를 추가하고 재시작

greenserver는 인증 정보를 읽거나 저장하거나 중계하지 않습니다. 구독 모드에서는 Claude 프로세스 환경에서 `ANTHROPIC_API_KEY`를 뺍니다.

## 명령어

```text
greenserver run --server URL [--token T] [--idle-watts W] [--max-watts W] [--state-dir DIR]
greenserver hook pre|post [--socket PATH]
greenserver mcp-approve [--socket PATH]
greenserver version
```

| 플래그 | 기본값 | 설명 |
|---|---|---|
| `--server` | | 백엔드 주소. `ws://`는 localhost에서만 허용 |
| `--token` | `GREENSERVER_TOKEN` | 에이전트 토큰. `ps`에 보이지 않도록 환경 변수를 권장 |
| `--idle-watts` | 15 | CPU 0%일 때의 추정 전력 |
| `--max-watts` | 75 | CPU 100%일 때의 추정 전력 |
| `--state-dir` | `~/.greenserver` | 소켓, 감사 로그, 최신 측정값 |

`hook`과 `mcp-approve`는 Claude Code가 실행하는 명령이라 직접 쓸 일이 없습니다.

## 전력 측정

- 베어메탈, 집 PC: RAPL 에너지 카운터의 변화량과 `nvidia-smi`로 실측합니다.
- 클라우드 VM이나 RAPL을 읽을 수 없는 경우: `idle + (max - idle) × CPU%`로 추정하고 `isEstimated: true`로 보냅니다. GPU만 실측되어도 전체 값은 추정으로 표시합니다.
- 실측 서버와 비교해 `--idle-watts`, `--max-watts`를 맞추면 추정 오차를 줄일 수 있습니다.
- 프로세스별 전력은 전체 전력을 CPU 점유율로 나눈 값입니다.

## 권한

| 단계 | 처리 |
|---|---|
| auto | 읽기와 상태 확인. 바로 실행 |
| approve | 상태를 바꾸는 명령과 알 수 없는 명령. 웹 승인 후 실행 |
| deny | 항상 차단 |

분류기는 `internal/classify`에 있고, 복합 명령을 나눠 가장 엄격한 결과를 따릅니다. 모르는 명령은 auto가 될 수 없습니다. PreToolUse 훅, 승인 도구, 에이전트가 같은 분류기를 각자 다시 호출합니다. 승인 대기는 10분이 지나거나 백엔드 연결이 끊기면 거부로 처리합니다.

### 되돌리기 명령

Claude는 approve 명령 끝에 주석으로 되돌리는 명령을 붙입니다.

```sh
sudo -n systemctl stop minecraft # undo: sudo -n systemctl start minecraft
```

- 주석은 쉘이 무시하므로 실행에 영향이 없고, 명령과 되돌리기가 한 문자열로 묶여 어긋나지 않습니다.
- 명령의 마지막 내용일 때만 인정합니다.
- 되돌리기 명령도 분류기를 거치며 approve 등급이어야 합니다. `true` 같은 빈 명령이나 금지 명령은 없는 것으로 처리합니다.
- 되돌리기가 없는 approve 명령은 웹에 묻지 않고 거부합니다.
- 파일 수정은 Edit 도구를 막고 Bash로만 하므로 모든 변경이 같은 규칙을 따릅니다.
- `undo` 메시지는 이 에이전트가 승인된 조치와 함께 기록한 문자열과 정확히 같을 때만 실행합니다. 그 외에는 실행하지 않고 `exitCode: 126`으로 응답합니다.

## 개발

```sh
go test ./...
GOOS=linux GOARCH=amd64 go build ./...
```

테스트는 가짜 WebSocket 서버와 PATH의 가짜 `claude` 스크립트로 돌아갑니다. 실제 `claude -p`나 분류 대상 명령을 실행하지 않습니다. macOS에서도 빌드되고 추정 모드로 동작합니다.
