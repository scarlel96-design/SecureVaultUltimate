!ifndef MUI_BGCOLOR
  !define MUI_BGCOLOR "101214"
!endif
!ifndef MUI_TEXTCOLOR
  !define MUI_TEXTCOLOR "F4F8FF"
!endif
!ifndef MUI_COMPONENTSPAGE_SMALLDESC
  !define MUI_COMPONENTSPAGE_SMALLDESC
!endif
!ifndef MUI_ABORTWARNING
  !define MUI_ABORTWARNING
!endif
!ifndef MUI_UNABORTWARNING
  !define MUI_UNABORTWARNING
!endif

!macro NSIS_HOOK_PREUNINSTALL
  MessageBox MB_YESNO|MB_ICONEXCLAMATION "SecureVault Ultimate can permanently destroy the security master database and all tracked encrypted protection stores before uninstall. Run military-standard secure purge now? This cannot be undone." IDNO securevault_skip_wipe
    ExecWait '"$INSTDIR\SecureVault Ultimate.exe" --uninstall-purge'
  securevault_skip_wipe:
!macroend
