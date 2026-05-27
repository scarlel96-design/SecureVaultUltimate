!macro NSIS_HOOK_PREUNINSTALL
  MessageBox MB_YESNO|MB_ICONEXCLAMATION "SecureVault Ultimate settings can allow secure destruction of vault data and tracked external .svu_lock stores. Run secure data wipe now? This cannot be undone." IDNO securevault_skip_wipe
    ExecWait '"$INSTDIR\SecureVault Ultimate.exe" --secure-uninstall-wipe'
  securevault_skip_wipe:
!macroend
