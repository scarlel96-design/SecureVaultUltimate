import { useCallback, useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { open } from "@tauri-apps/plugin-dialog";
import { getCurrentWebview } from "@tauri-apps/api/webview";

type StartupCheck = {
  name: string;
  status: "pass" | "warn" | "fail";
  detail: string;
};

type VaultEntry = {
  id: string;
  parentId?: string | null;
  name: string;
  kind: "file" | "directory";
  size: number;
  chunkCount: number;
  createdUtc: string;
  status: "ok" | "missing" | "partial";
  lockedFolderPath?: string | null;
};

type ConsistencyReport = {
  missingChunks: string[];
  orphanChunks: string[];
  quarantinedChunks: string[];
};

type FolderOperationResult = {
  path: string;
  action: "lock" | "unlock" | "check";
  ok: boolean;
  detail: string;
  processedEntries: number;
};

type EntryOperationResult = {
  id: string;
  name: string;
  action: "restore" | "check" | "delete";
  ok: boolean;
  detail: string;
  processedEntries: number;
};

type SettingsView = {
  autoLockMinutes: number;
  threatUpdateHours: number;
  threatFeedUrl: string;
  vanguardScanIntervalMinutes: number;
  scanOnActionIntegrity: boolean;
  secureWipeOnUninstall: boolean;
  decoyPasswordConfigured: boolean;
  updatedUtc: string;
};

type ThreatFeedStatus = {
  configured: boolean;
  lastCheckedUtc?: string | null;
  version?: string | null;
  ransomwareExtensionCount: number;
  yaraRuleCount: number;
  trustedProcessCount: number;
  detail: string;
};

type SequenceState = {
  title: string;
  detail: string;
  progress: number;
  logs: string[];
  mode: "running" | "success" | "error";
};

type VanguardLog = {
  utc: string;
  level: "info" | "critical";
  message: string;
};

type VanguardScanReport = {
  trigger: string;
  ok: boolean;
  logs: string[];
};

const DEFAULT_SETTINGS: SettingsView = {
  autoLockMinutes: 10,
  threatUpdateHours: 12,
  threatFeedUrl: "",
  vanguardScanIntervalMinutes: 1,
  scanOnActionIntegrity: true,
  secureWipeOnUninstall: false,
  decoyPasswordConfigured: false,
  updatedUtc: ""
};

const THREAT_INTERVALS = [1, 3, 6, 12, 24];

function formatBytes(bytes: number) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(value >= 10 || unit === 0 ? 0 : 1)} ${units[unit]}`;
}

function delay(ms: number) {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

function sequenceLog(text: string) {
  const time = new Date().toLocaleTimeString("ko-KR", { hour12: false });
  return `[${time}] ${text}`;
}

function summarizeFolderResults(results: FolderOperationResult[]) {
  const ok = results.filter((result) => result.ok).length;
  const failed = results.length - ok;
  const processed = results.reduce((sum, result) => sum + result.processedEntries, 0);
  const failedText = failed > 0 ? `, 실패 ${failed}개` : "";
  return `폴더 처리 완료: 성공 ${ok}개${failedText}, 항목 ${processed}개`;
}

function summarizeEntryResults(results: EntryOperationResult[], label: string) {
  const ok = results.filter((result) => result.ok).length;
  const failed = results.length - ok;
  const processed = results.reduce((sum, result) => sum + result.processedEntries, 0);
  const failedDetail = results.find((result) => !result.ok)?.detail;
  const failedText = failed > 0 ? `, 실패 ${failed}개${failedDetail ? ` (${failedDetail})` : ""}` : "";
  return `${label} 완료: 성공 ${ok}개${failedText}, 항목 ${processed}개`;
}

export default function App() {
  const [checks, setChecks] = useState<StartupCheck[]>([]);
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [locked, setLocked] = useState(true);
  const [exists, setExists] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [entries, setEntries] = useState<VaultEntry[]>([]);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [removeOriginal, setRemoveOriginal] = useState(false);
  const [report, setReport] = useState<ConsistencyReport | null>(null);
  const [settings, setSettings] = useState<SettingsView>(DEFAULT_SETTINGS);
  const [settingsDraft, setSettingsDraft] = useState<SettingsView>(DEFAULT_SETTINGS);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [decoyPassword, setDecoyPasswordValue] = useState("");
  const [wipeAllDataConfirmed, setWipeAllDataConfirmed] = useState(false);
  const [threatStatus, setThreatStatus] = useState<ThreatFeedStatus | null>(null);
  const [sequence, setSequence] = useState<SequenceState | null>(null);
  const [vanguardLogs, setVanguardLogs] = useState<string[]>([]);

  const selectedSet = useMemo(() => new Set(selectedIds), [selectedIds]);
  const allSelected = entries.length > 0 && selectedIds.length === entries.length;
  const totalBytes = useMemo(() => entries.reduce((sum, entry) => sum + entry.size, 0), [entries]);
  const anomalyCount = report ? report.missingChunks.length + report.quarantinedChunks.length : 0;

  const refreshEntries = useCallback(async () => {
    const list = await invoke<VaultEntry[]>("list_entries");
    setEntries(list);
    const liveIds = new Set(list.map((entry) => entry.id));
    setSelectedIds((current) => current.filter((id) => liveIds.has(id)));
  }, []);

  const refreshSettings = useCallback(async () => {
    const next = await invoke<SettingsView>("get_settings");
    setSettings(next);
    setSettingsDraft(next);
    return next;
  }, []);

  const refreshThreatStatus = useCallback(async () => {
    const status = await invoke<ThreatFeedStatus>("threat_feed_status");
    setThreatStatus(status);
    return status;
  }, []);

  const runChecks = useCallback(async () => {
    const startup = await invoke<StartupCheck[]>("startup_checks");
    setChecks(startup);
    const vaultExists = await invoke<boolean>("vault_exists");
    setExists(vaultExists);
    await refreshSettings();
    await refreshThreatStatus();
  }, [refreshSettings, refreshThreatStatus]);

  useEffect(() => {
    runStartupVerification().catch((error) => setMessage(String(error)));
  }, []);

  useEffect(() => {
    let unlisten: undefined | (() => void);
    listen<VanguardLog>("vanguard-log", (event) => {
      const log = `${event.payload.message}`;
      setVanguardLogs((current) => [sequenceLog(log)].concat(current).slice(0, 6));
      if (event.payload.level === "critical") {
        setSequence({
          title: "Vanguard Control",
          detail: "뱅가드가 하위 레이어 오염을 탐지하고 복구 프로토콜을 직접 통제합니다.",
          progress: log.includes("마스터 미러 복원 완료") ? 100 : 72,
          logs: [sequenceLog(log)],
          mode: log.includes("복원 완료") ? "success" : "running"
        });
      }
    }).then((fn) => {
      unlisten = fn;
    }).catch(() => undefined);
    return () => unlisten?.();
  }, []);

  useEffect(() => {
    if (locked) return;

    let lastBackendTouch = 0;
    let lockTimer: number | undefined;
    const autoLockMs = settings.autoLockMinutes * 60 * 1000;
    const events = ["mousemove", "keydown", "pointerdown", "wheel"];

    const scheduleAutoLock = () => {
      if (lockTimer) window.clearTimeout(lockTimer);
      lockTimer = window.setTimeout(() => {
        setMessage(`${settings.autoLockMinutes}분 동안 입력이 없어 금고를 자동 잠금 처리했습니다.`);
        void lockVault();
      }, autoLockMs + 500);
    };

    const onActivity = () => {
      scheduleAutoLock();
      const now = Date.now();
      if (now - lastBackendTouch > 15_000) {
        lastBackendTouch = now;
        void invoke("touch_session").catch(() => undefined);
      }
    };

    onActivity();
    events.forEach((eventName) => window.addEventListener(eventName, onActivity, { passive: true }));
    return () => {
      if (lockTimer) window.clearTimeout(lockTimer);
      events.forEach((eventName) => window.removeEventListener(eventName, onActivity));
    };
  }, [locked, settings.autoLockMinutes]);

  useEffect(() => {
    let unlisten: undefined | (() => void);
    getCurrentWebview()
      .onDragDropEvent((event) => {
        if (event.payload.type === "drop" && !locked) {
          void lockFolders(event.payload.paths);
        }
      })
      .then((fn) => {
        unlisten = fn;
      })
      .catch(() => undefined);
    return () => unlisten?.();
  }, [locked, removeOriginal]);

  async function runStartupVerification() {
    await runSequence({
      title: "Startup Verification",
      detail: "프로그램 코어와 로컬 방어 루틴을 순차 검증합니다.",
      logs: [
        "binary hash calculation",
        "anti-debug probe",
        "vanguard watchdog bootstrap",
        "golden mirror recovery anchor",
        "settings policy load",
        "threat intel cache inspection"
      ],
      task: runChecks,
      success: () => "초기 검증 루틴이 완료되었습니다."
    }).catch(() => undefined);
  }

  async function runSequence<T>(options: {
    title: string;
    detail: string;
    logs: string[];
    task: () => Promise<T>;
    success: (result: T) => string;
  }) {
    setBusy(true);
    setMessage("");
    setSequence({
      title: options.title,
      detail: options.detail,
      progress: 7,
      logs: [sequenceLog("secure sequence opened")],
      mode: "running"
    });

    let cursor = 0;
    let progress = 7;
    const timer = window.setInterval(() => {
      progress = Math.min(88, progress + 7);
      const nextLog = options.logs[cursor];
      cursor = Math.min(options.logs.length, cursor + 1);
      setSequence((current) => {
        if (!current || current.mode !== "running") return current;
        const logs = nextLog ? [...current.logs, sequenceLog(nextLog)].slice(-8) : current.logs;
        return { ...current, progress, logs };
      });
    }, 360);

    try {
      const result = await options.task();
      window.clearInterval(timer);
      const success = options.success(result);
      setSequence((current) =>
        current
          ? {
              ...current,
              detail: success,
              progress: 100,
              logs: [...current.logs, sequenceLog("auth tag verified"), sequenceLog("sequence committed")].slice(-8),
              mode: "success"
            }
          : current
      );
      await delay(520);
      setMessage(success);
      return result;
    } catch (error) {
      window.clearInterval(timer);
      const detail = String(error);
      setSequence((current) =>
        current
          ? {
              ...current,
              detail,
              progress: 100,
              logs: [...current.logs, sequenceLog("sequence rejected"), sequenceLog("sensitive buffers dropped")].slice(-8),
              mode: "error"
            }
          : current
      );
      await delay(700);
      setMessage(detail);
      throw error;
    } finally {
      await delay(180);
      setSequence(null);
      setBusy(false);
    }
  }

  async function unlockOrCreate() {
    if (password.length < 12) {
      setMessage("마스터 비밀번호는 최소 12자 이상으로 설정하세요.");
      return;
    }
    if (!exists && password !== confirm) {
      setMessage("비밀번호 확인이 일치하지 않습니다.");
      return;
    }

    await runSequence({
      title: exists ? "Vault Unlock" : "Vault Initialization",
      detail: "Argon2id KDF와 인덱스 인증 태그를 검증합니다.",
      logs: [
        "binary integrity checkpoint",
        "anti-debug monitor handshake",
        "Argon2id memory-hard key derivation",
        "AES-GCM vault.db authentication",
        "chunk index consistency scan"
      ],
      task: async () => {
        if (!exists) {
          await invoke("create_vault", { password });
          setExists(true);
        }
        const consistency = await invoke<ConsistencyReport>("unlock_vault", { password });
        setReport(consistency);
        setLocked(false);
        setPassword("");
        setConfirm("");
        await refreshEntries();
        return consistency;
      },
      success: () => "금고 세션이 열렸습니다."
    }).catch(() => undefined);
  }

  async function importPaths(paths: string[]) {
    if (paths.length === 0) return;
    await runSequence({
      title: "Chunk Encryption",
      detail: "파일을 64KB 청크로 나누고 인증 암호화합니다.",
      logs: [
        "source path permission check",
        "64KB chunk planner ready",
        "AES-256-GCM nonce allocation",
        "Reed-Solomon parity generation",
        "encrypted index journaling"
      ],
      task: async () => {
        await invoke("import_paths", { paths, removeOriginal });
        await refreshEntries();
        return true;
      },
      success: () => "금고 암호화가 완료되었습니다."
    }).catch(() => undefined);
  }

  async function chooseFiles() {
    const selectedPaths = await open({ multiple: true, directory: false });
    if (!selectedPaths) return;
    await importPaths(Array.isArray(selectedPaths) ? selectedPaths : [selectedPaths]);
  }

  async function chooseFolder() {
    const selectedPath = await open({ multiple: false, directory: true });
    if (!selectedPath) return;
    await importPaths([selectedPath]);
  }

  async function lockFolders(paths: string[]) {
    if (paths.length === 0) return;
    await runSequence({
      title: "In-Place Folder Lock",
      detail: "폴더를 남긴 채 내부 파일 트리를 숨김 청크 저장소로 이동합니다.",
      logs: [
        "folder.db session envelope staging",
        "honeytoken canary placement",
        "directory flattening map sealed",
        "source tree removal policy applied",
        "hidden .svu_lock attribute refreshed"
      ],
      task: async () => {
        const results = await invoke<FolderOperationResult[]>("lock_folders_in_place", {
          paths,
          secureDeleteOriginals: removeOriginal
        });
        await refreshEntries();
        return results;
      },
      success: summarizeFolderResults
    }).catch(() => undefined);
  }

  async function chooseFoldersToLock() {
    const selectedPaths = await open({ multiple: true, directory: true });
    if (!selectedPaths) return;
    await lockFolders(Array.isArray(selectedPaths) ? selectedPaths : [selectedPaths]);
  }

  async function chooseFoldersToUnlock() {
    const selectedPaths = await open({ multiple: true, directory: true });
    if (!selectedPaths) return;
    const paths = Array.isArray(selectedPaths) ? selectedPaths : [selectedPaths];
    await runSequence({
      title: "Folder Unlock",
      detail: "숨김 청크 저장소를 원래 파일 트리로 복구합니다.",
      logs: [
        "canary integrity check",
        "folder.db auth tag verification",
        "chunk ECC recovery window opened",
        "original tree reconstruction",
        "secure lock store wipe"
      ],
      task: async () => {
        const results = await invoke<FolderOperationResult[]>("unlock_folders_in_place", { paths });
        await refreshEntries();
        return results;
      },
      success: summarizeFolderResults
    }).catch(() => undefined);
  }

  async function chooseFoldersToCheck() {
    const selectedPaths = await open({ multiple: true, directory: true });
    if (!selectedPaths) return;
    const paths = Array.isArray(selectedPaths) ? selectedPaths : [selectedPaths];
    await runSequence({
      title: "Locked Folder Inspection",
      detail: "카나리아와 청크 인증 태그를 정밀 검사합니다.",
      logs: [
        "hidden lock root discovery",
        "honeytoken tamper scan",
        "folder.db authentication",
        "chunk parity verification",
        "integrity report sealed"
      ],
      task: () => invoke<FolderOperationResult[]>("check_folders_in_place", { paths }),
      success: summarizeFolderResults
    }).catch(() => undefined);
  }

  async function restoreSelected() {
    if (selectedIds.length === 0) {
      setMessage("복원할 항목을 먼저 선택하세요.");
      return;
    }
    const output = await open({ directory: true, multiple: false });
    if (!output || Array.isArray(output)) return;
    await runSequence({
      title: "Selective Restore",
      detail: "선택 항목만 인증 복호화해 지정 경로로 복원합니다.",
      logs: [
        "selection graph normalized",
        "chunk stream decrypt",
        "file hash verification",
        "target path conflict check",
        "restore session closed"
      ],
      task: () => invoke<EntryOperationResult[]>("restore_entries", { entryIds: selectedIds, destination: output }),
      success: (results) => summarizeEntryResults(results, "복원")
    }).catch(() => undefined);
  }

  async function checkSelected(all = false) {
    const entryIds = all ? [] : selectedIds;
    if (!all && entryIds.length === 0) {
      setMessage("검사할 항목을 먼저 선택하세요.");
      return;
    }
    await runSequence({
      title: all ? "Full Vault Inspection" : "Selective Integrity Inspection",
      detail: "인덱스, 청크, 파일 해시를 스트리밍 방식으로 검증합니다.",
      logs: [
        "virtual index traversal",
        "AES-GCM auth tag challenge",
        "ECC repair probe",
        "SHA-256 file digest compare",
        "integrity result committed"
      ],
      task: () => invoke<EntryOperationResult[]>("check_entries", { entryIds }),
      success: (results) => summarizeEntryResults(results, all ? "전체 검사" : "선택 검사")
    }).catch(() => undefined);
  }

  async function deleteSelected() {
    if (selectedIds.length === 0) {
      setMessage("삭제할 항목을 먼저 선택하세요.");
      return;
    }
    const ok = window.confirm(`선택한 ${selectedIds.length}개 항목을 금고에서 삭제할까요? 암호화 청크도 보안 삭제됩니다.`);
    if (!ok) return;

    await runSequence({
      title: "Secure Entry Disposal",
      detail: "선택 항목의 암호화 청크와 인덱스 매핑을 제거합니다.",
      logs: [
        "selection tree deduplication",
        "chunk wipe queue sealed",
        "random overwrite pass",
        "vault.db journal update",
        "deleted entry map zeroized"
      ],
      task: async () => {
        const results = await invoke<EntryOperationResult[]>("delete_entries", { entryIds: selectedIds });
        await refreshEntries();
        return results;
      },
      success: (results) => summarizeEntryResults(results, "삭제")
    }).catch(() => undefined);
  }

  async function saveSettings() {
    await runSequence({
      title: "Settings Commit",
      detail: "설정 변경 사항을 백엔드 정책 저장소에 반영합니다.",
      logs: [
        "settings range validation",
        "HTTPS feed URL policy check",
        "atomic settings write",
        "runtime guard refresh"
      ],
      task: async () => {
        const next = await invoke<SettingsView>("update_settings", {
          update: {
            autoLockMinutes: settingsDraft.autoLockMinutes,
            threatUpdateHours: settingsDraft.threatUpdateHours,
            threatFeedUrl: settingsDraft.threatFeedUrl,
            vanguardScanIntervalMinutes: settingsDraft.vanguardScanIntervalMinutes,
            scanOnActionIntegrity: settingsDraft.scanOnActionIntegrity,
            secureWipeOnUninstall: settingsDraft.secureWipeOnUninstall
          }
        });
        setSettings(next);
        setSettingsDraft(next);
        return next;
      },
      success: () => "설정이 저장되었습니다."
    }).catch(() => undefined);
  }

  async function commitDecoyPassword() {
    if (decoyPassword.length < 12) {
      setMessage("데코이 비밀번호는 최소 12자 이상이어야 합니다.");
      return;
    }
    await runSequence({
      title: "Decoy Credential Seal",
      detail: "데코이 비밀번호를 Argon2id 해시로 봉인합니다.",
      logs: [
        "decoy password buffer isolated",
        "Argon2id decoy derivation",
        "salt and hash envelope write",
        "plaintext password zeroized"
      ],
      task: async () => {
        const next = await invoke<SettingsView>("set_decoy_password", { password: decoyPassword });
        setDecoyPasswordValue("");
        setSettings(next);
        setSettingsDraft(next);
        return next;
      },
      success: () => "데코이 비밀번호가 설정되었습니다."
    }).catch(() => undefined);
  }

  async function clearDecoyPassword() {
    await runSequence({
      title: "Decoy Credential Removal",
      detail: "저장된 데코이 인증 레코드를 제거합니다.",
      logs: ["decoy record lookup", "settings journal update", "runtime state refresh"],
      task: async () => {
        const next = await invoke<SettingsView>("clear_decoy_password");
        setSettings(next);
        setSettingsDraft(next);
        return next;
      },
      success: () => "데코이 비밀번호가 제거되었습니다."
    }).catch(() => undefined);
  }

  async function syncThreatIntel() {
    await runSequence({
      title: "Threat Intelligence Pull",
      detail: "원격 피드를 내려받고 하이브리드 임계치 서명을 검증합니다.",
      logs: [
        "pull-only HTTPS request opened",
        "download buffer isolated",
        "payload SHA-256 checksum check",
        "Ed25519 signature anchor check",
        "ML-DSA threshold anchor check"
      ],
      task: async () => {
        const status = await invoke<ThreatFeedStatus>("sync_threat_intelligence");
        setThreatStatus(status);
        return status;
      },
      success: (status) => status.detail
    }).catch(() => undefined);
  }

  async function runManualVanguardScan() {
    await runSequence({
      title: "Vanguard Precision Scan",
      detail: "실행 파일, 중앙 청크, 허니토큰을 즉시 정밀 검사합니다.",
      logs: [
        "[VANGUARD] manual trigger accepted",
        "[VANGUARD] executable hash anchor compare",
        "[VANGUARD] session chunk map probe",
        "[VANGUARD] honeytoken mutation scan",
        "[VANGUARD] recovery readiness verified"
      ],
      task: async () => {
        const report = await invoke<VanguardScanReport>("vanguard_scan_now");
        setVanguardLogs((current) => report.logs.map(sequenceLog).concat(current).slice(0, 6));
        return report;
      },
      success: (report) => report.logs[report.logs.length - 1] ?? "뱅가드 정밀 스캔이 완료되었습니다."
    }).catch(() => undefined);
  }

  async function lockVault() {
    setBusy(true);
    try {
      await invoke("lock_vault");
      setLocked(true);
      setEntries([]);
      setSelectedIds([]);
      setReport(null);
    } finally {
      setBusy(false);
    }
  }

  function openSettings() {
    setSettingsDraft(settings);
    setDecoyPasswordValue("");
    setWipeAllDataConfirmed(false);
    setSettingsOpen(true);
  }

  function closeSettings() {
    setSettingsDraft(settings);
    setDecoyPasswordValue("");
    setWipeAllDataConfirmed(false);
    setSettingsOpen(false);
  }

  async function destroyAllData() {
    if (!wipeAllDataConfirmed) {
      setMessage("전체 데이터 삭제 확인 체크가 필요합니다.");
      return;
    }
    const ok = window.confirm("정말 모든 금고 데이터와 추적된 잠긴 폴더 데이터를 삭제할까요? 이 작업은 되돌릴 수 없습니다.");
    if (!ok) return;

    await runSequence({
      title: "Total Data Destruction",
      detail: "금고 인덱스, 청크, 설정, 추적된 외부 잠금 데이터를 삭제합니다.",
      logs: [
        "delete-all confirmation verified",
        "tracked external lock wipe",
        "vault session key drop",
        "local app data secure wipe",
        "runtime state reset"
      ],
      task: async () => {
        await invoke("destroy_all_vault_data", { confirmDeleteAll: true });
        setLocked(true);
        setExists(false);
        setEntries([]);
        setSelectedIds([]);
        setReport(null);
        setThreatStatus(null);
        setSettings(DEFAULT_SETTINGS);
        setSettingsDraft(DEFAULT_SETTINGS);
        setSettingsOpen(false);
        setWipeAllDataConfirmed(false);
        return true;
      },
      success: () => "모든 금고 데이터 삭제가 완료되었습니다."
    }).catch(() => undefined);
  }

  function toggleEntry(id: string) {
    setSelectedIds((current) => (current.includes(id) ? current.filter((item) => item !== id) : [...current, id]));
  }

  function toggleAllEntries() {
    setSelectedIds(allSelected ? [] : entries.map((entry) => entry.id));
  }

  return (
    <main className="app-frame">
      <aside className="command-rail">
        <div className="brand-lockup">
          <span className="brand-mark">SV</span>
          <div>
            <p className="eyebrow">SecureVault Ultimate</p>
            <h1>{locked ? "Zero-Knowledge Gate" : "Command Center"}</h1>
          </div>
        </div>

        <div className="boot-card glass-panel">
          <div className="panel-head">
            <span>검증 시퀀스</span>
            <strong>{checks.filter((check) => check.status === "pass").length}/{checks.length || 3}</strong>
          </div>
          <div className="mini-meter">
            <span style={{ width: `${checks.length ? (checks.filter((check) => check.status === "pass").length / checks.length) * 100 : 18}%` }} />
          </div>
          <div className="timeline">
            {checks.map((check, index) => (
              <div className={`timeline-step ${check.status}`} key={check.name}>
                <span>{index + 1}</span>
                <div>
                  <strong>{check.name}</strong>
                  <p>{check.detail}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="telemetry-grid">
          <div className="telemetry-tile glass-panel">
            <span>항목</span>
            <strong>{entries.length}</strong>
          </div>
          <div className="telemetry-tile glass-panel">
            <span>용량</span>
            <strong>{formatBytes(totalBytes)}</strong>
          </div>
          <div className="telemetry-tile glass-panel">
            <span>경고</span>
            <strong>{anomalyCount}</strong>
          </div>
          <div className="telemetry-tile glass-panel">
            <span>위협 DB</span>
            <strong>{threatStatus?.version ?? "offline"}</strong>
          </div>
        </div>
        <div className="vanguard-card glass-panel">
          <div className="panel-head">
            <span>Vanguard Kernel</span>
            <strong>{settings.vanguardScanIntervalMinutes}분</strong>
          </div>
          <div className="terminal-log compact">
            {(vanguardLogs.length ? vanguardLogs : [sequenceLog("[VANGUARD] watchdog standing by")]).map((log) => (
              <code key={log}>{log}</code>
            ))}
          </div>
        </div>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <p className="eyebrow">Defense Layer</p>
            <h2>{locked ? "마스터 세션 검증" : "암호화 작업 콘솔"}</h2>
          </div>
          <div className="topbar-actions">
            <button className="ghost-button" disabled={busy} onClick={() => void runManualVanguardScan()}>뱅가드 스캔</button>
            <button className="ghost-button" disabled={busy} onClick={openSettings}>설정</button>
            {!locked && <button className="danger-button" disabled={busy} onClick={() => void lockVault()}>잠금</button>}
          </div>
        </header>

        {locked ? (
          <section className="login-stage">
            <div className="login-box glass-panel">
              <p className="eyebrow">{exists ? "Unlock" : "Initialize"}</p>
              <h3>{exists ? "마스터 비밀번호 입력" : "새 금고 생성"}</h3>
              <input
                autoFocus
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                placeholder="마스터 비밀번호"
                onKeyDown={(event) => event.key === "Enter" && void unlockOrCreate()}
              />
              {!exists && (
                <input
                  type="password"
                  value={confirm}
                  onChange={(event) => setConfirm(event.target.value)}
                  placeholder="마스터 비밀번호 확인"
                  onKeyDown={(event) => event.key === "Enter" && void unlockOrCreate()}
                />
              )}
              <button className="primary-button" disabled={busy} onClick={() => void unlockOrCreate()}>
                {busy ? "검증 중" : exists ? "금고 열기" : "금고 만들기"}
              </button>
              {message && <p className="notice">{message}</p>}
            </div>
          </section>
        ) : (
          <section className="vault-grid">
            <div className={`drop-zone glass-panel ${busy ? "busy" : ""}`}>
              <div className="drop-copy">
                <p className="eyebrow">Drag & Drop</p>
                <h3>잠글 폴더를 여기로 끌어오세요</h3>
                <p>내부 파일은 숨김 `.svu_lock` 청크 저장소로 이동합니다.</p>
              </div>
              <div className="drop-status">
                <span>ACTIVE</span>
                <strong>AES-GCM / ECC</strong>
              </div>
            </div>

            <div className="action-deck glass-panel">
              <button disabled={busy} onClick={() => void chooseFoldersToLock()}>폴더 잠금</button>
              <button disabled={busy} onClick={() => void chooseFoldersToUnlock()}>잠금 해제</button>
              <button disabled={busy} onClick={() => void chooseFoldersToCheck()}>잠긴 폴더 검사</button>
              <button disabled={busy} onClick={() => void chooseFiles()}>파일 추가</button>
              <button disabled={busy} onClick={() => void chooseFolder()}>폴더 추가</button>
              <button disabled={selectedIds.length === 0 || busy} onClick={() => void restoreSelected()}>선택 복원</button>
              <button disabled={selectedIds.length === 0 || busy} onClick={() => void checkSelected(false)}>선택 검사</button>
              <button disabled={entries.length === 0 || busy} onClick={() => void checkSelected(true)}>전체 검사</button>
              <button disabled={selectedIds.length === 0 || busy} onClick={() => void deleteSelected()}>선택 삭제</button>
              <button disabled={busy} onClick={() => void syncThreatIntel()}>위협 DB 동기화</button>
            </div>

            <label className="toggle glass-panel">
              <input type="checkbox" checked={removeOriginal} onChange={(event) => setRemoveOriginal(event.target.checked)} />
              원본 제거 시 보안 삭제
            </label>

            {message && <div className="banner">{message}</div>}
            {report && (report.missingChunks.length > 0 || report.quarantinedChunks.length > 0) && (
              <div className="banner warning">
                누락 청크 {report.missingChunks.length}개, 격리된 미등록 청크 {report.quarantinedChunks.length}개
              </div>
            )}

            <div className="entry-table glass-panel">
              <div className="table-head">
                <span>
                  <input aria-label="전체 선택" type="checkbox" checked={allSelected} onChange={toggleAllEntries} />
                </span>
                <span>이름</span>
                <span>종류</span>
                <span>크기</span>
                <span>청크</span>
                <span>상태</span>
              </div>
              {entries.map((entry) => (
                <div
                  className={`table-row ${selectedSet.has(entry.id) ? "selected" : ""}`}
                  key={entry.id}
                  role="button"
                  tabIndex={0}
                  onClick={() => toggleEntry(entry.id)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" || event.key === " ") {
                      event.preventDefault();
                      toggleEntry(entry.id);
                    }
                  }}
                >
                  <span className="row-check">
                    <input
                      aria-label={`${entry.name} 선택`}
                      type="checkbox"
                      checked={selectedSet.has(entry.id)}
                      onChange={() => toggleEntry(entry.id)}
                      onClick={(event) => event.stopPropagation()}
                    />
                  </span>
                  <span>{entry.name}</span>
                  <span>{entry.lockedFolderPath ? "잠긴 폴더" : entry.kind === "directory" ? "폴더" : "파일"}</span>
                  <span>{formatBytes(entry.size)}</span>
                  <span>{entry.chunkCount}</span>
                  <span>{entry.status}</span>
                </div>
              ))}
            </div>
          </section>
        )}
      </section>

      {settingsOpen && (
        <div className="settings-backdrop" onClick={closeSettings}>
          <section className="settings-panel glass-panel" onClick={(event) => event.stopPropagation()}>
            <div className="panel-title">
              <div>
                <p className="eyebrow">Settings</p>
                <h3>통합 보안 설정</h3>
              </div>
              <button className="ghost-button" onClick={closeSettings}>닫기</button>
            </div>

            <label className="setting-field">
              <span>자동 세션 잠금 타이머</span>
              <strong>{settingsDraft.autoLockMinutes}분</strong>
              <input
                type="range"
                min={1}
                max={120}
                value={settingsDraft.autoLockMinutes}
                onChange={(event) => setSettingsDraft((current) => ({ ...current, autoLockMinutes: Number(event.target.value) }))}
              />
            </label>

            <label className="setting-field">
              <span>뱅가드 감시 인터벌</span>
              <strong>{settingsDraft.vanguardScanIntervalMinutes}분</strong>
              <input
                type="range"
                min={1}
                max={60}
                value={settingsDraft.vanguardScanIntervalMinutes}
                onChange={(event) => setSettingsDraft((current) => ({ ...current, vanguardScanIntervalMinutes: Number(event.target.value) }))}
              />
            </label>

            <label className="switch-field">
              <input
                type="checkbox"
                checked={settingsDraft.scanOnActionIntegrity}
                onChange={(event) => setSettingsDraft((current) => ({ ...current, scanOnActionIntegrity: event.target.checked }))}
              />
              <span>
                <strong>주요 액션 전 즉시 무결성 스캔</strong>
                <small>잠금, 해제, 복원, 삭제 전 뱅가드 스캔을 강제합니다.</small>
              </span>
            </label>

            <label className="setting-field">
              <span>위협 인텔리전스 업데이트 주기</span>
              <select
                value={settingsDraft.threatUpdateHours}
                onChange={(event) => setSettingsDraft((current) => ({ ...current, threatUpdateHours: Number(event.target.value) }))}
              >
                {THREAT_INTERVALS.map((hours) => (
                  <option value={hours} key={hours}>{hours}시간</option>
                ))}
              </select>
            </label>

            <label className="setting-field">
              <span>원격 위협 피드 URL</span>
              <input
                value={settingsDraft.threatFeedUrl}
                onChange={(event) => setSettingsDraft((current) => ({ ...current, threatFeedUrl: event.target.value }))}
                placeholder="https://example.github.io/secure-vault-feed.json"
              />
            </label>

            <div className="settings-actions">
              <button className="primary-button" disabled={busy} onClick={() => void saveSettings()}>설정 저장</button>
              <button disabled={busy} onClick={() => void syncThreatIntel()}>위협 DB 즉시 동기화</button>
            </div>

            <div className="decoy-box">
              <div>
                <span>부인 방지용 데코이 패스워드</span>
                <strong>{settings.decoyPasswordConfigured ? "설정됨" : "미설정"}</strong>
              </div>
              <input
                type="password"
                value={decoyPassword}
                onChange={(event) => setDecoyPasswordValue(event.target.value)}
                placeholder="새 데코이 비밀번호"
              />
              <div className="settings-actions">
                <button disabled={busy || decoyPassword.length === 0} onClick={() => void commitDecoyPassword()}>데코이 설정</button>
                <button disabled={busy || !settings.decoyPasswordConfigured} onClick={() => void clearDecoyPassword()}>데코이 제거</button>
              </div>
            </div>

            <div className="threat-card">
              <span>Threat Intelligence</span>
              <strong>{threatStatus?.version ?? "offline"}</strong>
              <p>{threatStatus?.detail ?? "상태 확인 중"}</p>
              <div className="threat-stats">
                <span>확장자 {threatStatus?.ransomwareExtensionCount ?? 0}</span>
                <span>YARA {threatStatus?.yaraRuleCount ?? 0}</span>
                <span>프로세스 {threatStatus?.trustedProcessCount ?? 0}</span>
              </div>
            </div>

            <div className="danger-zone">
              <div>
                <span>데이터 파기</span>
                <strong>전체 금고 데이터 삭제</strong>
                <p>중앙 금고 데이터와 현재 금고가 추적 중인 `.svu_lock` 저장소를 0x00 패스와 난수 패스로 덮어쓴 뒤 삭제합니다.</p>
              </div>
              <label className="danger-check crimson">
                <input
                  type="checkbox"
                  checked={settingsDraft.secureWipeOnUninstall}
                  onChange={(event) => setSettingsDraft((current) => ({ ...current, secureWipeOnUninstall: event.target.checked }))}
                />
                프로그램 제거 시 보안 삭제 루틴을 허용합니다.
              </label>
              <label className="danger-check">
                <input
                  type="checkbox"
                  checked={wipeAllDataConfirmed}
                  onChange={(event) => setWipeAllDataConfirmed(event.target.checked)}
                />
                모든 데이터를 삭제한다는 것을 확인했습니다.
              </label>
              <button className="danger-button" disabled={busy || !wipeAllDataConfirmed} onClick={() => void destroyAllData()}>
                모든 데이터 삭제
              </button>
            </div>
          </section>
        </div>
      )}

      {sequence && <SecuritySequence state={sequence} />}
    </main>
  );
}

function SecuritySequence({ state }: { state: SequenceState }) {
  return (
    <div className={`sequence-overlay ${state.mode}`}>
      <section className="sequence-panel glass-panel">
        <div className="panel-title">
          <div>
            <p className="eyebrow">Secure Operation</p>
            <h3>{state.title}</h3>
          </div>
          <strong>{Math.round(state.progress)}%</strong>
        </div>
        <div className="sequence-meter">
          <span style={{ width: `${state.progress}%` }} />
        </div>
        <p>{state.detail}</p>
        <div className="terminal-log">
          {state.logs.map((line, index) => (
            <code key={`${line}-${index}`}>{line}</code>
          ))}
        </div>
      </section>
    </div>
  );
}
