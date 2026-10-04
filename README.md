# ChromiumHistory v1.12.0

Windows 메모리 덤프에서 Chromium 계열 브라우저의 일반 방문 기록과
프로세스 메모리에 남은 URL 흔적을 복구하는 Volatility 3 플러그인입니다.
Microsoft Edge의 InPrivate 환경을 중심으로 실제 메모리 덤프를 이용해
검증했으며, 검색어를 미리 알거나 코드에 하드코딩하지 않아도 동작하도록
설계했습니다.

> 주의: 메모리에서 발견된 URL 문자열 하나만으로 실제 방문이나 시크릿 모드
> 사용을 확정할 수는 없습니다. 반드시 `Source`, `Mode`, `Persistence`와
> 구조적 근거를 함께 해석해야 합니다.

## 주요 기능

- Chromium `History` 데이터베이스 구조를 메모리에서 복구하여 일반 방문 기록 표시
- Chromium 브라우저 프로세스의 VAD에서 URL 및 검색 활동 흔적 탐색
- 지원되는 Edge 빌드에서 `OffTheRecordProfileImpl`과 렌더러 소유 관계를 이용해
  InPrivate 컨텍스트를 구조적으로 판별
- 탭을 닫은 뒤에도 관련 메모리 페이지와 렌더러가 남아 있으면 흔적 복구 가능
- Google이나 Bing 같은 특정 검색 엔진 및 특정 검색어에 의존하지 않는 범용 탐색
- 동일 활동의 메모리 복제본을 정규화하여 기본 출력에서 중복 억제
- Chrome, Edge, Brave, Opera, Vivaldi, Chromium 및 이름이 다른 Chromium 기반
  브라우저를 모듈 흔적으로 탐지
- 전체 물리 메모리 카빙과 HistoryDB 비교 기능 제공

## 설치

릴리스 압축 파일의 `plugins/chromiumhistory.py`를 Volatility 3에서 다음 두 방법
중 하나로 불러올 수 있습니다.

### 방법 1: 플러그인 경로를 명령행에서 지정

```powershell
python .\vol.py `
  --plugin-dirs .\ChromiumHistory-v1.12.0\plugins `
  -f .\memory.raw `
  chromiumhistory.ChromiumHistory
```

### 방법 2: Volatility 3의 Windows 플러그인 폴더에 복사

`plugins/chromiumhistory.py`를 다음 위치에 복사합니다.

```text
volatility3/framework/plugins/windows/chromiumhistory.py
```

그다음 아래처럼 실행합니다.

```powershell
python .\vol.py -f .\memory.raw windows.chromiumhistory.ChromiumHistory
```

## 기본 사용법

가장 먼저 실행할 명령은 다음과 같습니다.

```powershell
python .\vol.py -f 'C:\경로\memory.raw' windows.chromiumhistory.ChromiumHistory
```

기본 화면은 사람이 확인하기 쉽도록 핵심 9개 열만 표시합니다.

| 열 | 의미 |
|---|---|
| `Source` | HistoryDB, 프로세스 메모리 등 증거가 발견된 위치 |
| `PID` | 관련 프로세스 ID. 물리 메모리 단독 흔적은 `-1` |
| `Process` | 관련 브라우저 프로세스 이름 |
| `Mode` | `Regular`, `InPrivate`, `Unknown` 등의 브라우징 컨텍스트 |
| `Activity` | 복원된 검색어, 페이지 제목 또는 대표 URL |
| `Host` | URL 호스트 이름 |
| `Visits` | HistoryDB에 남은 방문 횟수 |
| `LastVisitKST` | 복구 가능한 경우의 마지막 방문 시각(한국 표준시) |
| `Persistence` | 일반 HistoryDB와의 비교 및 영속성 판정 |

CSV 분석이나 모든 포렌식 필드가 필요하면 `--full-output`을 사용합니다.

```powershell
python .\vol.py -r csv -f .\memory.raw `
  windows.chromiumhistory.ChromiumHistory --full-output |
  Out-File .\chromium-full.csv -Encoding utf8
```

## 목적별 실행 예시

일반 HistoryDB 기록만 확인:

```powershell
python .\vol.py -f .\memory.raw `
  windows.chromiumhistory.ChromiumHistory --history-only
```

HistoryDB에 없는 프로세스 메모리 흔적만 확인:

```powershell
python .\vol.py -f .\memory.raw `
  windows.chromiumhistory.ChromiumHistory --memory-only
```

닫힌 탭을 포함하여 프로세스와 물리 메모리에 남은 URL 흔적을 폭넓게 탐색:

```powershell
python .\vol.py -f .\memory.raw `
  windows.chromiumhistory.ChromiumHistory --recover-closed
```

HistoryDB와 비교하여 영속 기록 여부까지 판정:

```powershell
python .\vol.py -f .\memory.raw `
  windows.chromiumhistory.ChromiumHistory `
  --compare-history --physical-only --physical-browser-context
```

증거성이 약한 문자열까지 모두 검토해야 할 때만 `--raw-url-strings`를 사용하세요.
출력량과 오탐 후보가 크게 늘어날 수 있습니다.

## 시크릿/InPrivate 결과 해석

- `HistoryDB + Regular`: 일반 브라우징 기록으로 해석할 수 있는 영속 레코드입니다.
- 구조적으로 확인된 `InPrivate`: 지원되는 브라우저 빌드에서 해당 렌더러가
  Off-The-Record 프로필에 속한다는 메모리 구조 근거가 확인된 경우입니다.
- `MemoryOnly`: HistoryDB에서 같은 URL을 찾지 못했다는 뜻일 뿐, 이것만으로
  시크릿 방문을 확정하지는 않습니다.
- `PhysicalURLString`: 물리 메모리에서 URL 모양의 문자열이 발견됐다는 뜻입니다.
  원래 프로세스나 실제 최상위 방문 여부는 단독으로 확정할 수 없습니다.
- 결과가 없다고 해서 방문이 없었다는 뜻은 아닙니다. 탭 또는 프로세스 종료 후
  메모리 페이지가 해제·덮어쓰기 되었거나 덤프에 포함되지 않았을 수 있습니다.

브라우저 업데이트로 내부 구조가 달라질 수 있으므로, 정확한 InPrivate 구조 판별은
지원되는 빌드에서 가장 신뢰할 수 있습니다. 알 수 없는 빌드는 임의로
`InPrivate`라고 추정하지 않고 `Unknown`으로 남깁니다.

## 테스트

```powershell
python .\tests\test_chromiumhistory.py
python .\tests\test_mock_integration.py
```

현재 버전은 단위 및 모의 통합 테스트 36개를 통과했으며, 35.9GB Windows 메모리
덤프에서 일반 HistoryDB 레코드와 Edge InPrivate 활동을 검증했습니다. 저장소의
`media/ChromiumHistory-v1.12.0-validation.mp4`에서 실제 실행 화면을 확인할 수
있습니다.

---

아래는 버전별 구현 및 검증 세부 기록입니다.

## Version 1.12.0: readable default output

The default terminal view now contains nine focused columns: `Source`, `PID`,
`Process`, `Mode`, `Activity`, `Host`, `Visits`, `LastVisitKST`, and
`Persistence`. `Activity` prefers a decoded search query or page title and is
limited to 96 characters, preventing long URLs and forensic metadata from
making the ordinary table unreadable.

Use `--full-output` when exporting CSV or when all 28 forensic fields (full
URL, offset, scoring reasons, mode evidence, canonical activity, and UTC/KST
timestamps) are required:

```powershell
python .\vol.py -r csv -f .\memory.raw `
  windows.chromiumhistory.ChromiumHistory --full-output |
  Out-File .\chromium-full.csv -Encoding utf8
```

This is a rendering-only change. Recovery, private-mode attribution, history
comparison, and canonical deduplication are unchanged.

## Version 1.11.0: independent SQLite record decoder

The persisted-History path now uses a new forward SQLite table-leaf cell
decoder. It reads the declared payload size, rowid, record-header size, serial
types, and record body in file-format order. It no longer uses the earlier
`sqlite_help.py` API, reverse scanning helpers, fixed column-header walk, or
legacy `ChromeHistory.calculate()` flow.

The implementation was written against SQLite's public
[Database File Format](https://sqlite.org/fileformat2.html). It validates
reserved serial types, nine-byte varints, signed 24/48-bit integers, payload
boundaries, and the `INTEGER PRIMARY KEY` rowid alias represented by a NULL
record column.

Validation results:

- 32 unit tests passed, including synthetic table-leaf cells and truncation.
- The 35.9 GB final-validation image recovered 98 HistoryDB rows.
- All 98 URL, title, visit-count, typed-count, and UTC timestamp tuples exactly
  matched the previous validated result.
- No legacy SQLite helper names or project-module imports remain.

## Final-validation note (2026-10-02)

The default no-hint workflow restricts automatic process discovery to known
browser executables, combines PsList with PsScan, and identifies supported Edge
builds from any surviving sibling-process PE header.

The 35.9 GB WinPmem validation capture had no resident renderer private-flag
pages.  The plugin therefore recovered the exact-build
`OffTheRecordProfileImpl` object in the browser process and matched
`RenderProcessHostImpl::renderer_client_id` to its owning `BrowserContext`.
This attributed renderer client 30 to the recovered OTR profile without using
a search keyword, PID, or nearby `InPrivate` text heuristic.  The ordinary
default command produced 98 regular HistoryDB rows and one structurally owned
InPrivate memory row; regular renderer and shared browser-cache strings were
suppressed. A renderer is marked `Regular` only when its BrowserContext equals
the OTR object's recovered original-profile pointer; unrelated profile objects
remain `Unknown`. Unknown builds are still never guessed.

Volatility 3 plugin for recovering persisted Chromium history and URL strings
left in browser process memory, including possible Incognito/InPrivate traces.

## Version 1.10.0: no-hint browser detection

The ordinary command now excludes Chromium applications such as WebView2,
Electron, ChatGPT, and Adobe CEF unless `--include-chromium-apps` is supplied.
It automatically combines PsList with PsScan so active renderers omitted from
PsList can still be inspected. For supported browser builds, the private flag
RVA is selected from the in-memory PE timestamp and SizeOfImage. Unknown builds
remain `Unknown` and are never guessed. Edge 154.0.4258.48 is included.
For that build, a PDB-derived OTR-profile/RenderProcessHost ownership fallback
is used when the direct renderer flag page is not resident.

### Closed-tab validation

A second 35.9 GB WinPmem capture was taken after two newly searched InPrivate
tabs were closed while an earlier InPrivate tab remained open. Both new,
distinct searches were recovered as `InPrivate`. Windows still reported both
associated Edge renderers as live at acquisition time, demonstrating recovery
after tab closure (but not yet after renderer-process termination). Default
output deduplicates the same canonical InPrivate activity across renderer PIDs;
`--raw-url-strings` retains the per-PID copies for forensic inspection.

```powershell
python .\vol.py -f .\memory.raw windows.chromiumhistory.ChromiumHistory
```

By default, ordinary renderer URL strings are suppressed because regular
navigation is already represented by HistoryDB. Structurally attributed
InPrivate activity remains visible. Use `--raw-url-strings` for the complete
process-memory carving view.

## Version 1.9.0: activity-focused output

Version 1.9.0 adds `ArtifactClass` and `CanonicalActivity`. By default it
reports only structurally recognized activity and suppresses browser-owned
internal URLs, invalid/template strings, static resources, background requests,
and unattributed document-shaped strings. Recognized search URLs are
deduplicated by provider host and parsed query, so one search action is not
reported once for each result-mode or filter URL. No search keyword is
hardcoded.

The remaining classes are deliberately conservative:

- `SearchActivity`: a structurally recognized search URL with a parsed query.
- `ProbableUserNavigation`: History/serialized/fetch-navigation evidence.
- `StaleOrUnattributed`: document-shaped text without proof that it was visited.
- `BackgroundOrEmbedded` and `TemplateOrInternal`: suppressed unless
  `--raw-url-strings` is supplied.

Use `--include-unattributed` to retain document-shaped strings without activity
proof while still suppressing obvious browser noise. Use `--raw-url-strings`
for forensic review of every recoverable URL-shaped string. `BrowsingMode`
`=InPrivate` still identifies the process context, not the origin or
user-visible visit status of every allocation in that process.

## Version 1.8.0: structural private-mode attribution

Version 1.8.0 can attribute process-memory URL remnants to a Chromium renderer
whose private-mode flag is set. New output columns are `BrowsingMode` and
`ModeEvidence`:

- `HistoryDB` rows are `Regular`, because Chromium private browsing does not
  persist its navigation history to the ordinary History database.
- A renderer whose build-matched private flag is `1` is `InPrivate`.
- A renderer whose flag is `0` is `Regular`.
- Browser processes, inaccessible flags, and runs without a supplied flag RVA
  remain `MixedOrNotApplicable` or `Unknown` rather than being guessed.

The exact flag RVA is browser-build-specific and must be derived from the
matching executable/PDB. It is not a universal constant and must not be copied
to a different browser version. For Microsoft Edge 153.0.4234.48, DBH reported
the symbol at `0x14e6b6cc` using its synthetic module base `0x01000000`, so the
RVA passed to the plugin was `0x13e6b6cc`.

Active renderer processes can be absent from `windows.pslist`. Version 1.8.0
therefore accepts comma-separated virtual `_EPROCESS` offsets recovered by a
targeted `windows.psscan` run through `--eprocess-offsets`.

Example for the validated Edge 153.0.4234.48 dump:

```powershell
python .\vol.py -q -r csv -f .\memory.raw `
  windows.chromiumhistory.ChromiumHistory `
  --eprocess-offsets 0xd00e808ae080 0xd00eba6c50c0 0xd00ec11a50c0 0xd00eef1f0080 0xd00ef08b4080 `
  --private-flag-rva 0x13e6b6cc `
  --browser-module msedge.dll `
  --skip-history --recover-closed --process-only |
  Out-File .\chromium-inprivate.csv -Encoding utf8
```

When a private flag RVA is supplied, URL carving is limited to private VADs;
mapped DLL and executable-image strings are excluded. Comma/semicolon-joined
embedded URL lists are also split before parsing to reduce false records.

Important: `BrowsingMode=InPrivate` proves that the remnant came from a VAD of
a renderer whose private-mode flag was set. A standalone carved URL string is
still not proof of a user-visible top-level visit. Use
`--navigation-structures` when stronger serialized-navigation evidence is
required; a zero-result run means no matching structure survived or the
browser build's serialization layout is not yet supported.

Version 1.5.0 adds experimental `--navigation-structures`. Unlike plain URL
carving, this mode requires the surrounding fields written by Chromium's
`SerializedNavigationEntry::WriteToPickle`: entry index, length-prefixed URL,
UTF-16 title, PageState, transition type, type mask, referrer, original URL,
timestamp, and HTTP status. Static-resource-shaped URLs are suppressed. A
match is materially stronger than a standalone string, but absence is not
proof that a private visit did not happen; the structure may have been freed
or overwritten before acquisition.

Use `--history-only` to output only ordinary persisted Chromium History rows.
Omit it to combine ordinary history with process-memory evidence, or use
`--navigation-structures` without `--skip-history` to combine ordinary history
with only strictly validated navigation structures.

`--physical-only --physical-browser-context` performs keyword-independent
physical-memory recovery. It retains URLs only when nearby generic evidence
such as a Chromium browser process name, a cluster of related URLs, or HTTP
metadata is present, while penalizing unit-test, source-code, and notification
text. These rows are labelled `BrowserNetworkContext`: they establish probable
browser/network activity, not by themselves a top-level visit or private mode.

```powershell
python .\vol.py -q -r csv -f .\memory.raw `
  windows.chromiumhistory.ChromiumHistory `
  --skip-history --physical-only --physical-browser-context `
  --max-results 10000 |
  Out-File .\chromium-physical-context.csv -Encoding utf8
```

Version 1.7.0 adds `ActivityRole` and `PersistenceAssessment` columns. Generic
Fetch Metadata and HTML-response artifacts can promote a row to
`ProbableTopLevelNavigation`; document-shaped URLs without those explicit
artifacts remain `PossibleDocumentRequest`. Static resources and common
background paths are labelled `SubresourceOrBackground`.

Use `--compare-history` to perform a real HistoryDB scan before assigning
`PersistedHistoryCorroborated` or `NotInRecoveredHistory`. Without that scan,
the plugin reports `NotCompared` and does not imply private browsing.

```powershell
python .\vol.py -q -r csv -f .\memory.raw `
  windows.chromiumhistory.ChromiumHistory `
  --compare-history --physical-only --physical-browser-context `
  --max-results 10000 |
  Out-File .\chromium-activity-history-compare.csv -Encoding utf8
```

## Browser detection

By default the plugin does not rely only on a fixed executable-name list. It
accepts common browser names as a fast path and inspects loaded modules for
Chromium/CEF markers such as `chrome.dll`, `chrome_elf.dll`, `msedge.dll`, and
`libcef.dll`. This allows differently named portable Chromium browsers to be
included automatically.

CEF and Electron applications also use Chromium components and may therefore be
included. Restrict the run when necessary with `--pid`, `--process-name`, or
`--process-names`.

## Installation

Extract the release archive beside the Volatility 3 directory. The archive
keeps the plugin in `plugins/chromiumhistory.py`, so it can be loaded without
modifying the Volatility installation:

```powershell
python .\vol.py `
  --plugin-dirs .\ChromiumHistory-v1.12.0\plugins `
  -f .\memory.raw `
  chromiumhistory.ChromiumHistory
```

Alternatively, copy `plugins/chromiumhistory.py` into
`volatility3/framework/plugins/windows/` and invoke it as
`windows.chromiumhistory.ChromiumHistory`.

## Run

```powershell
python .\vol.py `
  --plugin-dirs .\ChromiumHistory-v1.12.0\plugins `
  -f .\memory.raw `
  chromiumhistory.ChromiumHistory
```

Only display URLs found in browser memory but absent from recovered HistoryDB
rows:

```powershell
python .\vol.py `
  --plugin-dirs .\ChromiumHistory-v1.12.0\plugins `
  -f .\memory.raw `
  chromiumhistory.ChromiumHistory `
  --memory-only
```

Explicit process-name override:

```powershell
... chromiumhistory.ChromiumHistory --process-name custombrowser.exe
```

Multiple explicit names:

```powershell
... chromiumhistory.ChromiumHistory `
  --process-names "custombrowser.exe,anotherbrowser.exe"
```

Fast targeted VAD scan without the full HistoryDB or physical fallback scans:

```powershell
... chromiumhistory.ChromiumHistory `
  --process-name msedge.exe --memory-only --skip-history --process-only `
  --url-filter "apple,pear"
```

`--skip-history` makes every recovered URL uncorroborated, so `MemoryOnly`
means only that it came from process memory. `--url-filter` performs a
case-insensitive substring filter and can therefore include unrelated URLs
such as `apple.com`; inspect full search URLs when drawing conclusions.

Recover arbitrary URL remnants from both Chromium process VADs and the full
physical-memory layer without knowing a URL, domain, or search term:

```powershell
... chromiumhistory.ChromiumHistory --recover-closed
```

This is the primary closed/private-tab carving mode. `Host`, `Path`, and
`RawQuery` are populated for every parsed URL. `SearchEngine` and `SearchQuery`
are optional enrichment only when a recognized search URL is encountered; the
recovery itself is not limited to searches. Physical hits cannot be attributed
reliably to their original process and may also contain URL text copied into
other applications, so `PhysicalURLString` is evidence of a remnant rather
than proof of a particular browser mode.

For a conservative, structured view use navigation candidate mode:

```powershell
... chromiumhistory.ChromiumHistory --navigation-candidates
```

This correlates recovered HistoryDB rows, scans private browser VADs rather
than mapped executable/DLL regions, suppresses common static resources and
templates, and emits `EvidenceClass`, `CandidateScore`, and
`CandidateReasons`. History rows include `LastVisitUTC` and `LastVisitKST`.
Scores are based primarily on provenance, not on favoring one search engine;
identical Google/Bing/etc. URLs receive the same treatment when their source
context is the same.

Candidate mode includes Chrome, Edge, Brave, Opera, Vivaldi, and Chromium by
default. Non-browser Chromium/CEF/Electron programs (for example ChatGPT.exe)
are excluded to prevent chat text from being promoted to browser evidence.
Use `--include-chromium-apps` when those applications are intentionally in
scope.

In `--recover-closed`, `--recover-searches`, or `--skip-history` mode the
sources are deliberately named `ProcessURLString` and `PhysicalURLString`.
These rows prove only that URL-shaped text was recovered. They are not browser
history and do not by themselves establish a visit or private browsing.

## Result interpretation

- `HistoryDB`: persisted SQLite-shaped browser-history record
- `ProcessMemory`: URL present in process memory and HistoryDB
- `MemoryOnly`: URL present in process memory but absent from recovered HistoryDB

`MemoryOnly` is a private-mode candidate, not proof. It can also represent a
normal page not yet written to History, an internal request, cache data, or a
partial acquisition. Browser identity comes from the `Process` column.

The plugin scans HTTP(S) plus common Chromium internal schemes in UTF-8 and
UTF-16LE. Private-mode recovery still depends on the relevant pages remaining
resident when memory is acquired.

If no process-memory URL is recovered, the plugin automatically falls back to
the base physical-memory layer. Use `--scan-physical` to run that scan even when
VAD results exist. Physical hits are reported as `PhysicalMemory` or
`PhysicalMemoryOnly`, with PID `-1` and process `PhysicalMemory`, because stale
pages cannot be attributed reliably to their former process or browser.

## Tests without a real dump

```powershell
python .\test_chromiumhistory.py
python .\test_mock_integration.py
```

The mock integration test drives the process-memory recovery path using a
synthetic Edge VAD containing ASCII and UTF-16LE private URL remnants. The VAD
path was also validated against a real Edge memory image containing a unique
Google search URL.
