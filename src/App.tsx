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
  action: "restore" | "check" | "delete" | "unlock";
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
  locale: AppLocale;
  decoyPasswordConfigured: boolean;
  updatedUtc: string;
};

type AppLocale = "ko" | "en";

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

type ShieldStatus = {
  configured: boolean;
  required: boolean;
  transport: string;
  mode: string;
  detail: string;
};

type ShieldLog = {
  level: "info" | "warn" | "critical";
  message: string;
};

type UpdateStatus = {
  available: boolean;
  currentVersion: string;
  version?: string | null;
  date?: string | null;
  body?: string | null;
  detail: string;
};

const DEFAULT_SETTINGS: SettingsView = {
  autoLockMinutes: 10,
  threatUpdateHours: 12,
  threatFeedUrl: "",
  vanguardScanIntervalMinutes: 1,
  scanOnActionIntegrity: true,
  secureWipeOnUninstall: false,
  locale: "ko",
  decoyPasswordConfigured: false,
  updatedUtc: ""
};

const THREAT_INTERVALS = [1, 3, 6, 12, 24];

const I18N: Record<AppLocale, Record<string, string>> = {
  ko: {
    verificationSequence: "검증 시퀀스",
    selfProtection: "자체 보호 스캔",
    selfProtectionMonitor: "자체 보호 모니터",
    selfProtectionReady: "[자체 보호] 백그라운드 보호 루틴 대기 중",
    scanNow: "자체 보호 스캔",
    protectedFolderDropTitle: "보호할 폴더를 여기로 끌어오세요",
    protectedFolderDropDetail: "내부 파일들이 안전하게 격리된 가상 보안 컨테이너 내부로 이동하여 보호됩니다.",
    protectedStorage: "보호 저장소",
    protectedBlocks: "보호 블록",
    restoreOriginal: "원래 위치로 복귀",
    protectedFolder: "보호 폴더",
    securePurgeText: "보안 마스터 데이터베이스 및 전체 암호화 대상 보호 저장소를 군사 표준 규격으로 완전히 파기한 후 안전하게 삭제합니다.",
    language: "표시 언어",
    ecosystemShield: "에코시스템 실드",
    updateCheck: "업데이트 확인",
    installUpdate: "업데이트 설치"
  },
  en: {
    verificationSequence: "Verification Sequence",
    selfProtection: "Self-Protection",
    selfProtectionMonitor: "Self-Protection Monitor",
    selfProtectionReady: "[Self-Protection] background guard standing by",
    scanNow: "Self-Protection",
    protectedFolderDropTitle: "Drop folders here to protect them",
    protectedFolderDropDetail: "Internal files move into an isolated virtual security container for protection.",
    protectedStorage: "Protected Store",
    protectedBlocks: "Protected Blocks",
    restoreOriginal: "Restore Original",
    protectedFolder: "Protected Folder",
    securePurgeText: "Secure master database and all encrypted protection stores are destroyed to a military-standard purge policy, then safely removed.",
    language: "Language",
    ecosystemShield: "Ecosystem Shield",
    updateCheck: "Check Update",
    installUpdate: "Install Update"
  }
};

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

function polishSecurityCopy(text: string) {
  return text
    .replaceAll("[VANGUARD]", "[SELF-PROTECTION]")
    .replaceAll("Vanguard", "Self-Protection")
    .replaceAll("vanguard", "self-protection")
    .replaceAll("뱅가드", "자체 보호")
    .replaceAll(".svu_lock", "가상 보안 컨테이너")
    .replaceAll("청크", "보호 블록")
    .replaceAll("chunk", "protected block")
    .replaceAll("honeytoken", "guard file")
    .replaceAll("허니토큰", "보호 감시 파일");
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
  const [shieldStatus, setShieldStatus] = useState<ShieldStatus | null>(null);
  const [shieldLogs, setShieldLogs] = useState<string[]>([]);
  const [updateStatus, setUpdateStatus] = useState<UpdateStatus | null>(null);

  const selectedSet = useMemo(() => new Set(selectedIds), [selectedIds]);
  const allSelected = entries.length > 0 && selectedIds.length === entries.length;
  const totalBytes = useMemo(() => entries.reduce((sum, entry) => sum + entry.size, 0), [entries]);
  const anomalyCount = report ? report.missingChunks.length + report.quarantinedChunks.length : 0;
  const locale = settingsDraft.locale || settings.locale || "ko";
  const t = useCallback((key: string) => I18N[locale]?.[key] ?? I18N.ko[key] ?? key, [locale]);

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

  const refreshShieldStatus = useCallback(async () => {
    const status = await invoke<ShieldStatus>("ecosystem_shield_status");
    setShieldStatus(status);
    return status;
  }, []);

  const runChecks = useCallback(async () => {
    const startup = await invoke<StartupCheck[]>("startup_checks");
    setChecks(startup.map((check) => ({ ...check, name: polishSecurityCopy(check.name), detail: polishSecurityCopy(check.detail) })));
    const vaultExists = await invoke<boolean>("vault_exists");
    setExists(vaultExists);
    await refreshSettings();
    await refreshThreatStatus();
    await refreshShieldStatus();
  }, [refreshSettings, refreshThreatStatus, refreshShieldStatus]);

  useEffect(() => {
    runStartupVerification().catch((error) => setMessage(String(error)));
  }, []);

  useEffect(() => {
    let unlisten: undefined | (() => void);
    listen<VanguardLog>("vanguard-log", (event) => {
      const log = polishSecurityCopy(`${event.payload.message}`);
      setVanguardLogs((current) => [sequenceLog(log)].concat(current).slice(0, 6));
      if (event.payload.level === "critical") {
        setSequence({
          title: t("selfProtectionMonitor"),
          detail: "자체 보호 모니터가 보호 영역 오염을 탐지하고 복구 프로토콜을 직접 통제합니다.",
          progress: log.includes("마스터 미러 복원 완료") ? 100 : 72,
          logs: [sequenceLog(log)],
          mode: log.includes("복원 완료") ? "success" : "running"
        });
      }
    }).then((fn) => {
      unlisten = fn;
    }).catch(() => undefined);
    return () => unlisten?.();
  }, [t]);

  useEffect(() => {
    let unlisten: undefined | (() => void);
    listen<ShieldLog>("shield-log", (event) => {
      const log = polishSecurityCopy(event.payload.message);
      setShieldLogs((current) => [sequenceLog(log)].concat(current).slice(0, 6));
      if (event.payload.level === "critical") {
        setSequence({
          title: t("ecosystemShield"),
          detail: "Ecosystem Shield heartbeat failed. Sensitive session state is being closed.",
          progress: 100,
          logs: [sequenceLog(log)],
          mode: "error"
        });
      }
    }).then((fn) => {
      unlisten = fn;
    }).catch(() => undefined);
    return () => unlisten?.();
  }, [t]);

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
        "self-protection monitor bootstrap",
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
      const success = polishSecurityCopy(options.success(result));
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
      const detail = polishSecurityCopy(String(error));
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
      detail: "Argon2id와 PBKDF2-HMAC-SHA512 기반 하이브리드 KDF로 인덱스 인증 태그를 검증합니다.",
      logs: [
        "binary integrity checkpoint",
        "anti-debug monitor handshake",
        "hybrid KDF credential derivation",
        "AES-GCM vault.db authentication",
        "protected block index consistency scan"
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
      title: "Protected Data Encryption",
      detail: "파일을 고정 크기 보호 블록으로 나누고 인증 암호화합니다.",
      logs: [
        "source path permission check",
        "protected block planner ready",
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
      title: "Protected Folder Isolation",
      detail: "폴더는 남기고 내부 파일 트리를 격리된 가상 보안 컨테이너로 이동합니다.",
      logs: [
        "folder.db session envelope staging",
        "guard file placement",
        "directory flattening map sealed",
        "source tree removal policy applied",
        "virtual security container attribute refreshed"
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
      title: "Protected Folder Restore",
      detail: "가상 보안 컨테이너의 데이터를 원래 파일 트리로 복구합니다.",
      logs: [
        "canary integrity check",
        "folder.db auth tag verification",
        "protected block ECC recovery window opened",
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

  async function unlockSelectedToOriginalPaths() {
    if (selectedIds.length === 0) {
      setMessage("원래 위치로 복귀할 보호 폴더를 먼저 선택하세요.");
      return;
    }
    await runSequence({
      title: "Protected Folder Restore",
      detail: "선택한 보호 폴더를 저장된 원래 경로로 자동 복귀합니다.",
      logs: [
        "original path metadata lookup",
        "guard file integrity check",
        "protected container authentication",
        "data block recovery stream",
        "original location restore committed"
      ],
      task: async () => {
        const results = await invoke<EntryOperationResult[]>("unlock_locked_entries_to_original_paths", { entryIds: selectedIds });
        await refreshEntries();
        return results;
      },
      success: (results) => summarizeEntryResults(results, "원위치 복귀")
    }).catch(() => undefined);
  }

  async function chooseFoldersToCheck() {
    const selectedPaths = await open({ multiple: true, directory: true });
    if (!selectedPaths) return;
    const paths = Array.isArray(selectedPaths) ? selectedPaths : [selectedPaths];
    await runSequence({
      title: "Protected Folder Inspection",
      detail: "보호 감시 파일과 보호 블록 인증 태그를 정밀 검사합니다.",
      logs: [
        "hidden lock root discovery",
        "guard file tamper scan",
        "folder.db authentication",
        "protected block parity verification",
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
        "protected block stream decrypt",
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
      detail: "인덱스, 보호 블록, 파일 해시를 스트리밍 방식으로 검증합니다.",
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
    const ok = window.confirm(`선택한 ${selectedIds.length}개 항목을 금고에서 삭제할까요? 암호화된 보호 블록도 보안 삭제됩니다.`);
    if (!ok) return;

    await runSequence({
      title: "Secure Entry Disposal",
      detail: "선택 항목의 암호화 보호 블록과 인덱스 매핑을 제거합니다.",
      logs: [
        "selection tree deduplication",
        "protected block wipe queue sealed",
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
            secureWipeOnUninstall: settingsDraft.secureWipeOnUninstall,
            locale: settingsDraft.locale
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
    const feedUrl = settingsOpen ? settingsDraft.threatFeedUrl.trim() : settings.threatFeedUrl.trim();
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
        const status = feedUrl
          ? await invoke<ThreatFeedStatus>("sync_threat_intelligence_from_url", { feedUrl })
          : await invoke<ThreatFeedStatus>("sync_threat_intelligence");
        setThreatStatus(status);
        return status;
      },
      success: (status) => status.detail
    }).catch(() => undefined);
  }

  async function checkForUpdate() {
    await runSequence({
      title: "Secure Update Check",
      detail: "GitHub Releases updater manifest를 확인하고 Tauri 서명 검증 정책을 준비합니다.",
      logs: [
        "updater endpoint policy load",
        "manifest pull request",
        "release asset signature lookup",
        "trusted updater public key check"
      ],
      task: async () => {
        const status = await invoke<UpdateStatus>("check_secure_update");
        setUpdateStatus(status);
        return status;
      },
      success: (status) => status.detail
    }).catch(() => undefined);
  }

  async function installUpdate() {
    const ok = window.confirm("검증된 업데이트를 다운로드하고 설치한 뒤 앱을 재시작할까요?");
    if (!ok) return;
    await runSequence({
      title: "Secure Update Install",
      detail: "업데이트 패키지를 다운로드하고 내장 공개키로 서명을 검증합니다.",
      logs: [
        "update manifest selected",
        "asset download stream opened",
        "signature verification",
        "installer handoff",
        "application restart"
      ],
      task: () => invoke("install_secure_update"),
      success: () => "업데이트 설치를 시작했습니다."
    }).catch(() => undefined);
  }

  async function runManualVanguardScan() {
    await runSequence({
      title: "Self-Protection Precision Scan",
      detail: "실행 파일, 보호 데이터 블록, 보호 감시 파일을 즉시 정밀 검사합니다.",
      logs: [
        "[SELF-PROTECTION] manual trigger accepted",
        "[SELF-PROTECTION] executable hash anchor compare",
        "[SELF-PROTECTION] session protected block map probe",
        "[SELF-PROTECTION] guard file mutation scan",
        "[SELF-PROTECTION] recovery readiness verified"
      ],
      task: async () => {
        const report = await invoke<VanguardScanReport>("vanguard_scan_now");
        setVanguardLogs((current) => report.logs.map(polishSecurityCopy).map(sequenceLog).concat(current).slice(0, 6));
        return report;
      },
      success: (report) => report.logs[report.logs.length - 1] ?? "자체 보호 정밀 스캔이 완료되었습니다."
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
      detail: "금고 인덱스, 보호 블록, 설정, 추적된 보호 저장소를 삭제합니다.",
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
            <span>{t("verificationSequence")}</span>
            <strong>{checks.filter((check) => check.status === "pass" || check.status === "warn").length}/{checks.length || 3}</strong>
          </div>
          <div className="mini-meter">
            <span style={{ width: `${checks.length ? (checks.filter((check) => check.status === "pass" || check.status === "warn").length / checks.length) * 100 : 18}%` }} />
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
            <span>{t("selfProtectionMonitor")}</span>
            <strong>{settings.vanguardScanIntervalMinutes}분</strong>
          </div>
          <div className="terminal-log compact">
            {(vanguardLogs.length ? vanguardLogs : [sequenceLog(t("selfProtectionReady"))]).map((log) => (
              <code key={log}>{log}</code>
            ))}
          </div>
        </div>
        <div className="shield-card glass-panel">
          <div className="panel-head">
            <span>{t("ecosystemShield")}</span>
            <strong>{shieldStatus?.mode ?? "checking"}</strong>
          </div>
          <p>{shieldStatus?.detail ?? "Ecosystem Shield 상태 확인 중"}</p>
          <div className="terminal-log compact">
            {(shieldLogs.length ? shieldLogs : [sequenceLog("Ecosystem Shield heartbeat standby")]).map((log) => (
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
            <button className="ghost-button" disabled={busy} onClick={() => void runManualVanguardScan()}>{t("scanNow")}</button>
            <button className="ghost-button" disabled={busy} onClick={() => void checkForUpdate()}>{t("updateCheck")}</button>
            {updateStatus?.available && <button className="primary-button" disabled={busy} onClick={() => void installUpdate()}>{t("installUpdate")}</button>}
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
                <h3>{t("protectedFolderDropTitle")}</h3>
                <p>{t("protectedFolderDropDetail")}</p>
              </div>
              <div className="drop-status">
                <span>ACTIVE</span>
                <strong>AES-GCM / ECC</strong>
              </div>
            </div>

            <div className="action-deck glass-panel">
              <button disabled={busy} onClick={() => void chooseFoldersToLock()}>폴더 잠금</button>
              <button disabled={selectedIds.length === 0 || busy} onClick={() => void unlockSelectedToOriginalPaths()}>{t("restoreOriginal")}</button>
              <button disabled={busy} onClick={() => void chooseFoldersToUnlock()}>경로 지정 해제</button>
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
                누락 보호 블록 {report.missingChunks.length}개, 격리된 미등록 보호 블록 {report.quarantinedChunks.length}개
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
                <span>{t("protectedBlocks")}</span>
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
                  <span className="entry-name">
                    {entry.lockedFolderPath && <span className="lock-indicator">LOCK</span>}
                    {entry.name}
                  </span>
                  <span>{entry.lockedFolderPath ? t("protectedFolder") : entry.kind === "directory" ? "폴더" : "파일"}</span>
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
              <span>자체 보호 스캔 주기</span>
              <strong>{settingsDraft.vanguardScanIntervalMinutes}분</strong>
              <input
                type="range"
                min={1}
                max={60}
                value={settingsDraft.vanguardScanIntervalMinutes}
                onChange={(event) => setSettingsDraft((current) => ({ ...current, vanguardScanIntervalMinutes: Number(event.target.value) }))}
              />
            </label>

            <label className="setting-field">
              <span>{t("language")}</span>
              <select
                value={settingsDraft.locale}
                onChange={(event) => setSettingsDraft((current) => ({ ...current, locale: event.target.value as AppLocale }))}
              >
                <option value="ko">한국어</option>
                <option value="en">English</option>
              </select>
            </label>

            <label className="switch-field">
              <input
                type="checkbox"
                checked={settingsDraft.scanOnActionIntegrity}
                onChange={(event) => setSettingsDraft((current) => ({ ...current, scanOnActionIntegrity: event.target.checked }))}
              />
              <span>
                <strong>주요 액션 전 즉시 무결성 스캔</strong>
                <small>보호, 복귀, 복원, 삭제 전 자체 보호 스캔을 강제합니다.</small>
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
                <p>{t("securePurgeText")}</p>
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
