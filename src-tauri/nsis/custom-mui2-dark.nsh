; SecureVault Ultimate MUI2 dark theme reference.
; The active build path uses src-tauri/nsis-hooks.nsh because Tauri includes
; installer hooks before the generated Modern UI pages are declared.

!define MUI_BGCOLOR "101214"
!define MUI_TEXTCOLOR "F4F8FF"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_RIGHT
!define MUI_HEADERIMAGE_BITMAP "installer-assets\header.bmp"
!define MUI_WELCOMEFINISHPAGE_BITMAP "installer-assets\sidebar.bmp"
!define MUI_UNWELCOMEFINISHPAGE_BITMAP "installer-assets\sidebar.bmp"
!define MUI_COMPONENTSPAGE_SMALLDESC
!define MUI_ABORTWARNING
!define MUI_UNABORTWARNING
