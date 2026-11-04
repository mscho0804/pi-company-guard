# pi-company-guard

회사 SSH 서버에서 [pi coding agent](https://pi.dev)를 쓸 때 필요한 **가드레일**과 **작업 완료 알림**을 제공하는 pi 패키지입니다.

| 확장 | 기능 |
|---|---|
| `extensions/guardrail.ts` | 민감 파일 접근 차단 · 위험 명령 차단/확인 · 데이터 유출(egress) 감지 · 운영 서버 읽기 전용 모드 · 도구 출력 시크릿 마스킹 · 감사 로그 |
| `extensions/notify.ts` | 작업 완료 시 **Microsoft Teams**(Workflows 웹훅) 알림 + **터미널 벨**(SSH 너머 로컬 터미널까지 전달) |

> [!IMPORTANT]
> 이 가드레일은 **실수 방지 + 감사 기록**용 안전망입니다. 패턴 기반이라 의도적인 우회(인코딩, 난독화 등)를 완벽히 막을 수는 없습니다.
> 실질적인 보호는 pi 전용 OS 계정, 파일 권한, 컨테이너/샌드박스와 **함께** 사용하세요.

---

## 설치

```bash
# git 패키지로 설치 (권장) — ~/.pi/agent/settings.json 에 등록됨
pi install git:github.com/mscho0804/pi-company-guard

# 또는 한 번만 시험
pi -e git:github.com/mscho0804/pi-company-guard

# 또는 직접 복사 (index.ts 가 두 확장을 모두 로드)
git clone https://github.com/mscho0804/pi-company-guard ~/.pi/agent/extensions/pi-company-guard
```

요구사항: pi `@earendil-works/pi-coding-agent` ≥ 1.4, Node ≥ 22.18, (Teams 알림용) `curl`.

설치 후 pi 안에서:

```
/guard          # 가드레일 상태, 이번 세션 차단/승인/마스킹 통계
/guard reload   # 설정 다시 읽기
/notify-test    # Teams + 터미널 알림 테스트
```

---

## 1. 가드레일

### 민감 파일 차단 (read · write · edit · grep · find · ls · bash · 커스텀/MCP 도구)

| 분류 | 기본 패턴 (일부) | 동작 |
|---|---|---|
| 시크릿 | `.env`, `.env.*`, `*.pem`, `*.key`, `id_rsa*`, `~/.ssh/**`, `~/.aws/**`, `~/.kube/**`, `~/.docker/config.json`, `.netrc`, `.git-credentials`, `~/.pi/agent/auth.json`, `/etc/shadow`, `/proc/*/environ` … | **읽기·쓰기 모두 차단** |
| 쓰기 보호 | `~/.pi/agent/**`(가드 설정·확장 자체), `~/.bashrc`, `~/.zshrc`, `.git/config`, `.git/hooks/**`, `/etc/**`, `/usr/**` … | 읽기 허용, **쓰기 차단** |
| 예외 | `.env.example`, `.env.sample`, `.env.template`, `*.pub` | 허용 |

- 상대경로/`..`/`~` 정규화, **심볼릭 링크 실제 경로**까지 검사합니다.
- bash 명령 안에 등장하는 경로(`cat ~/.ssh/id_rsa`, `curl -F f=@.env …`, `source .env`)도 검사합니다.
- `grep --glob "*.env"` 같은 일괄 읽기도 차단합니다.

### 위험 명령

| 수준 | 규칙 id → 예시 |
|---|---|
| **차단** (묻지 않음) | `rm-root` `rm -rf /`, `~`, `*` · `mkfs` · `dd-device` · `device-write` · `fork-bomb` · `pipe-to-shell` `curl … \| sh` · `power` `reboot`/`shutdown` · `sensitive-path` |
| **확인** (사용자 승인 필요) | `rm-recursive` · `sudo` · `chmod-777` · `chown-recursive` · `git-force-push` · `git-reset-hard` · `git-clean` · `git-branch-delete` · `git-history-rewrite` · `kubectl-mutate` · `helm-mutate` · `terraform-mutate` · `docker-destructive` · `service-control` · `kill-process` · `crontab-remove` · `firewall` · `sql-destructive` (`DROP`, `TRUNCATE`, WHERE 없는 `DELETE`) · `env-dump` (`env`, `printenv`) · `secret-tools` (`kubectl get secret`, `gh auth token`, `aws configure get` …) |
| **확인** (egress) | `egress-transfer` (`scp`, `sftp`, `nc`, 원격 `rsync`) · `egress-upload` (`curl -d/-F/-T/-X POST`) · `egress-host` (허용 목록 밖 호스트로 curl/wget) |

- `pi -p` 같은 **UI 없는 모드에서는 "확인" 규칙도 차단**됩니다 (`nonInteractive: "block"`).
- `r''m -rf /`, `c'a't .env` 같은 따옴표 난독화는 정규화 후 검사합니다.
- 차단 시 모델에게 "우회하지 말고 사용자에게 요청하라"는 메시지를 돌려줍니다.

### 운영 서버 읽기 전용 모드

`readOnlyHostPattern: "prod|prd"` 처럼 설정하면 hostname이 일치하는 서버에서:
`write`/`edit` 도구 차단, 파일을 바꾸는 bash(`rm`, `mv`, `cp`, `>`, `sed -i`, `git commit` …) 차단, 모든 "확인" 규칙이 "차단"으로 승격됩니다.

### 시크릿 마스킹 (`tool_result`)

모든 도구 출력은 **LLM으로 전송되기 전에** 마스킹됩니다:
private key 블록, AWS/GitHub/GitLab/Slack/OpenAI/Anthropic/Google/Stripe/npm 토큰, JWT, `Authorization: Bearer …`, URL 안의 비밀번호(`postgres://u:pw@`), Teams/Slack 웹훅 URL,
`DB_PASSWORD=…` 같은 dotenv 라인, `"password": "…"` 같은 따옴표 리터럴.
`const token = getToken()` 같은 일반 코드는 건드리지 않도록 설계했습니다.

### 감사 로그

`~/.pi/agent/logs/company-guard-audit.jsonl` (권한 600) 에 JSON Lines로 기록:

```json
{"ts":"2026-11-04T10:50:32Z","user":"ms","host":"dev-01","cwd":"/home/ms/app","event":"tool_call","tool":"bash","target":"git push --force","decision":"confirm-approved","rules":["git-force-push"]}
```

`decision`: `allow` · `block` · `confirm-approved` · `confirm-denied` · `redacted` · `error`. 대상 문자열도 마스킹되며 파일 내용은 기록하지 않습니다.

---

## 2. 알림

### Teams (Workflows 웹훅)

1. Teams 채널 `⋯` → **Workflows** → **"Post to a channel when a webhook request is received"** 템플릿 → URL 복사
2. 서버에서 URL을 환경변수로 등록 (파일에 남기지 않기 위해 env 권장):
   ```bash
   echo "export PI_TEAMS_WEBHOOK_URL='https://...'" >> ~/.bashrc_secrets && chmod 600 ~/.bashrc_secrets
   ```
3. **pi 연결 전에 환경 점검**:
   ```bash
   node scripts/check-notify.ts            # 프록시 설정 출력, 터미널 벨, 테스트 카드 전송
   ```
   - `Could not resolve host` / timeout → 외부망 차단: `HTTPS_PROXY` 설정 또는 IT에 허용 요청
   - 401/403/404 → URL 오류 또는 Workflow 비활성

동작:
- `notify.minDurationSec`(기본 30초) 이상 걸린 작업이 끝나면(`agent_settled`) 카드를 보냅니다.
- 카드에는 **메타데이터만** 들어갑니다: 호스트, 디렉토리, 소요 시간, 도구 호출 수, 차단 수, 모델. 프롬프트·출력·파일 내용은 절대 포함하지 않습니다.
- 전송은 `curl -K -`로 하며, URL/본문을 stdin으로 넘겨 **`ps`에 웹훅 URL이 노출되지 않습니다**. `HTTPS_PROXY`/`NO_PROXY`를 그대로 따르고, curl이 없으면 `fetch`로 대체합니다.
- 전송 실패 시 pi 화면에 경고를 띄우고, 터미널 알림은 그대로 동작합니다.

### 터미널 (Teams가 막혀 있을 때의 대안, 기본 ON)

- **BEL(`\a`)**: SSH → tmux/screen → 로컬 터미널까지 그대로 전달됩니다. Windows Terminal은 탭에 🔔 표시 + 작업표시줄 깜빡임, iTerm2/VS Code 터미널도 지원합니다.
- **탭 제목**: 작업 중 `⏳ pi — host`, 완료 시 `✅ pi — host`.
- 선택: `terminal.osc` = `osc777`(WezTerm/Ghostty/iTerm2), `osc9`(iTerm2/ConEmu), `osc99`(Kitty) 데스크톱 알림. tmux 안이면 자동으로 passthrough로 감쌉니다 (`set -g allow-passthrough on` 필요).

> tmux 사용 시 벨이 전달되도록: `set -g monitor-bell on`, `set -g bell-action any`

---

## 설정

병합 순서 (뒤가 우선, **배열은 기본값에 추가**되므로 기본 보호를 실수로 지우지 않습니다):

1. 내장 기본값
2. `/etc/pi/company-guard.json` — 회사/관리자 공통 기준
3. `~/.pi/agent/company-guard.json` — 개인
4. `$PI_GUARD_CONFIG`

**저장소(.pi/) 단위 설정은 일부러 지원하지 않습니다** — clone한 저장소가 가드레일을 완화할 수 없어야 하기 때문입니다.
JSON 문법 오류가 있으면 해당 파일은 무시되고 기본값이 유지되며(fail-closed), 시작 시 경고가 뜹니다.

예시: [`config/company-guard.example.json`](config/company-guard.example.json)

| 키 | 기본값 | 설명 |
|---|---|---|
| `guard.sensitivePaths` / `writeProtectedPaths` / `allowPaths` | 위 표 참고 | glob. `/` 없으면 파일명, `**/x/**` 임의 깊이, `/abs`, `~/` |
| `guard.workspaceOnly` | `false` | cwd(와 임시 디렉토리) 밖 파일 접근 차단 |
| `guard.readOnlyHostPattern` | `""` | hostname 정규식 → 읽기 전용 모드 |
| `guard.egressAllowedHosts` | github, npm, pypi, localhost | `*.corp.com` 와일드카드 |
| `guard.nonInteractive` | `"block"` | UI 없을 때 "확인" 규칙 처리 |
| `guard.redact` / `extraRedactPatterns` | `true` / `[]` | 출력 마스킹, 사내 패턴(사번 등) 추가 |
| `guard.disabledRules` / `blockRules` | `[]` | 규칙 id 끄기 / "확인" → "차단" 승격 |
| `audit.enabled` / `audit.path` | `true` / `~/.pi/agent/logs/…` | 감사 로그 |
| `notify.minDurationSec` | `30` | 이보다 짧은 작업은 알리지 않음 |
| `notify.teams.webhookUrlEnv` | `PI_TEAMS_WEBHOOK_URL` | 웹훅 URL 환경변수 (`webhookUrl`로 직접 지정도 가능) |
| `notify.terminal.bell` / `osc` / `title` | `true` / `"off"` / `true` | 터미널 알림 |

---

## 개발 / 테스트

```bash
npm install
npm test          # 140개 테스트
npm run typecheck
```

- `test/paths|commands|redact|notify.test.ts` — 단위 테스트 (웹훅은 로컬 HTTP 서버 + **실제 curl**로 검증)
- `test/extensions.test.ts` — 확장을 가짜 ExtensionAPI에 올려 이벤트로 구동 (확인/거부, UI 없음, 읽기 전용 호스트, 감사 로그, 알림)
- `test/e2e.test.ts` — **실제 pi 런타임**(SDK + jiti 확장 로더)을 pi-ai의 `faux` 스크립트 모델로 구동:
  `.env` 읽기 차단 → `cat ~/.ssh/id_rsa` 차단 → AWS 키 마스킹 → `rm -rf` 비대화형 차단 → 정상 읽기 통과 → 모델 대화 기록에 시크릿 없음 → Teams 웹훅 수신 → 감사 로그 확인

## License

MIT
