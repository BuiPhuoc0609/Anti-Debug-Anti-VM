# Anti-Debug-Anti-VM

## antix1

<img width="1242" height="147" alt="image" src="https://github.com/user-attachments/assets/33c94c09-6aea-4e5e-921d-04b5081663ff" />

mở ida:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS NUMPAD "+" TO EXPAND]

  if ( argc == 2 )
  {
    __sidt(v17);
    if ( (v18 & 0xFF000000) != 0xFF000000 )
    {
      HIWORD(v19) = -8531;
      v20 = 0;
      __asm { sldt    word ptr [ebp+var_8] }
      if ( v19 == -559087616 )
      {
        __sgdt(v15);
        if ( (v16 & 0xFF000000) != 0xFF000000 )
        {
          __asm { str     word ptr [ebp+argc] }
          if ( argca != 0x4000 )
          {
            _EAX = 1;
            __asm
            {
              cpuid
              xorps   xmm0, xmm0
            }
            __asm { movq    [ebp+var_24], xmm0 }
            if ( _ECX >= 0 )
            {
              ArgList = (char *)malloc(0x29u);
              *(_DWORD *)ArgList = 0;
              sub_2C1260(argv[1], byte_2C3AFC, ArgList);
              sub_2C1100("%s", ArgList);
              return 0;
            }
          }
        }
      }
    }
  }
  else if ( argc == 1 )
  {
    malloc(0xAu);
    v12 = sub_2C19F0();
    ArgList_1 = (char *)malloc(0x55u);
    *(_DWORD *)ArgList_1 = 0;
    sub_2C1260(v12, byte_2C3B48, ArgList_1);
    sub_2C1100("%s", ArgList_1);
    return 0;
  }
  return -1;
}
```

Ta thấy chương trình có 2 nhánh, nhánh 1 là nhánh có args và nhánh 2 là không có args:
- Không có args thì chương trình sẽ khởi tạo key `v12` từ `sub_2C19F0()` rồi sau đó decrypt RC4 `byte_2C3B48` bằng hàm `sub_2C1260`.
- ở nhánh có args thì chương trình sẽ trực tiếp decrypt rc4 ciphertext `byte_2C3AFC` với key là args ta nhận vào

Ta phân tích hàm khởi tạo key_rc4 `sub_2C19F0`:

```c
char *sub_2C19F0()
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS NUMPAD "+" TO EXPAND]

  n4 = 4;
  p_C_1 = (char *)::malloc(0xAu);
  HARDWARE__DEVICEMAP__Scsi__Scsi_Port_0__Scsi_Bus_0__Target_Id_0 = L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\"
                                                                     "Target Id 0\\Logical Unit Id 0";
  p_lpValueName_1[0] = L"Identifier";
  p_lpValueName = (const WCHAR **)p_lpValueName_1;
  p_lpValueName_1[1] = L"VMWARE";
  p_lpValueName_1[2] = L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 1\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0";
  n5 = 5;
  p_lpValueName_1[3] = L"Identifier";
  p_lpValueName_1[4] = L"VMWARE";
  p_lpValueName_1[5] = L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 2\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0";
  p_lpValueName_1[6] = L"Identifier";
  p_lpValueName_1[7] = L"VMWARE";
  p_lpValueName_1[8] = L"SYSTEM\\ControlSet001\\Control\\SystemInformation";
  p_lpValueName_1[9] = L"SystemManufacturer";
  p_lpValueName_1[10] = L"VMWARE";
  p_lpValueName_1[11] = L"SYSTEM\\ControlSet001\\Control\\SystemInformation";
  p_lpValueName_1[12] = L"SystemProductName";
  p_lpValueName_1[13] = L"VMWARE";
  do
  {
    if ( sub_2C14B0(*(p_lpValueName - 1), *p_lpValueName, p_lpValueName[1]) )
      ++n4;
    p_lpValueName += 3;
    --n5;
  }
  while ( n5 );
  p_C = p_C_1;
  *p_C_1 = aAbcdefghijlkmn[n4];
  SOFTWARE__VMware__Inc.__VMware_Tools = L"SOFTWARE\\VMware, Inc.\\VMware Tools";
  phkResult = 0;
  memset(v66, 0, sizeof(v66));
  if ( RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\VMware, Inc.\\VMware Tools", 0, KEY_READ, &phkResult) )
  {
    n13 = 13;
  }
  else
  {
    RegCloseKey(phkResult);
    n13 = 14;
  }
  n15 = 15;
  p_C[1] = aAbcdefghijlkmn[n13];
  pszFile[0] = L"system32\\drivers\\vmmouse.sys";
  pszFile[1] = L"system32\\drivers\\vmhgfs.sys";
  pszFile[2] = L"system32\\drivers\\vm3dmp.sys";
  pszFile[3] = L"system32\\drivers\\vmci.sys";
  pszFile[4] = L"system32\\drivers\\vmhgfs.sys";
  pszFile[5] = L"system32\\drivers\\vmmemctl.sys";
  pszFile[6] = L"system32\\drivers\\vmmouse.sys";
  pszFile[7] = L"system32\\drivers\\vmrawdsk.sys";
  pszFile[8] = L"system32\\drivers\\vmusbmouse.sys";
  memset(Buffer, 0, sizeof(Buffer));
  memset(pszDest, 0, sizeof(pszDest));
  GetWindowsDirectoryW(Buffer, 0x104u);
  for ( i = 0; i < 9; ++i )
  {
    PathCombineW(pszDest, Buffer, pszFile[i]);
    FileAttributesW = GetFileAttributesW(pszDest);
    v8 = FileAttributesW != -1 && (FileAttributesW & 0x10) == 0;
    n15_1 = n15 + 1;
    if ( !v8 )
      n15_1 = n15;
    n15 = n15_1;
  }
  p_C[2] = aAbcdefghijlkmn[n15_1];
  memset(FileName, 0, sizeof(FileName));
  wcscpy(pszFile_1, (const wchar_t *)&pszFile_);
  memset(v85, 0, sizeof(v85));
  if ( sub_2C1410() )
    ExpandEnvironmentStringsW(L"%ProgramW6432%", Dst, 0x104u);
  else
    SHGetSpecialFolderPathW(0, Dst, 38, 0);
  PathCombineW(FileName, Dst, pszFile_1);
  v10 = GetFileAttributesW(FileName);
  if ( v10 == -1 || (v11 = (v10 & 0x10) == 0, n86 = aAbcdefghijlkmn[22], v11) )
    n86 = aAbcdefghijlkmn[21];
  v13 = 0;
  p_C[3] = n86;
  v71[0] = &off_2C3660;
  n4_1 = 0;
  v71[1] = L"00:05:69";
  v71[2] = &off_2C367C;
  v71[3] = L"00:0c:29";
  v71[4] = &off_2C3698;
  v71[5] = L"00:1C:14";
  v71[6] = &off_2C36B4;
  v71[7] = L"00:50:56";
  do
  {
    if ( sub_2C1590((_BYTE *)v71[2 * n4_1]) )
      ++v13;
    ++n4_1;
  }
  while ( n4_1 < 4 );
  n6_2 = 0;
  p_C[4] = aAbcdefghijlkmn[v13];
  SizePointer = 648;
  ProcessHeap = GetProcessHeap();
  AdapterInfo = (struct _IP_ADAPTER_INFO *)HeapAlloc(ProcessHeap, 0, 0x288u);
  AdapterInfo_2 = AdapterInfo;
  if ( !AdapterInfo )
  {
    sub_2C19C0((wchar_t *)L"Error allocating memory needed to call GetAdaptersinfo.\n", ArgList);
    n6_2 = -1;
    goto LABEL_43;
  }
  AdaptersInfo = GetAdaptersInfo(AdapterInfo, &SizePointer);
  if ( AdaptersInfo == 111 )
  {
    AdapterInfo_3 = AdapterInfo_2;
    hHeap = GetProcessHeap();
    HeapFree(hHeap, 0, AdapterInfo_3);
    SizePointer_1 = SizePointer;
    hHeap_1 = GetProcessHeap();
    AdapterInfo_1 = (struct _IP_ADAPTER_INFO *)HeapAlloc(hHeap_1, 0, SizePointer_1);
    AdapterInfo_2 = AdapterInfo_1;
    if ( !AdapterInfo_1 )
    {
      sub_2C1100("Error allocating memory needed to call GetAdaptersinfo\n");
      n6_2 = 1;
      goto LABEL_43;
    }
    AdaptersInfo = GetAdaptersInfo(AdapterInfo_1, &SizePointer);
  }
  if ( !AdaptersInfo )
  {
    AdapterInfo_4 = (const CHAR *)AdapterInfo_2;
    n6_1 = 0;
    do
    {
      cchWideChar = MultiByteToWideChar(0, 0, AdapterInfo_4 + 268, -1, 0, 0);
      Size = 2 * cchWideChar + 2;
      psz1_1 = (WCHAR *)::malloc(Size);
      psz1 = psz1_1;
      if ( psz1_1 )
      {
        for ( j = psz1_1; Size; --Size )
        {
          *(_BYTE *)j = 0;
          j = (WCHAR *)((char *)j + 1);
        }
        MultiByteToWideChar(0, 0, AdapterInfo_4 + 268, -1, psz1_1, cchWideChar);
        psz1_2 = (WCHAR *)psz1;
        if ( !StrCmpIW(psz1, L"VMWare") )
          n6_1 = 1;
        free(psz1_2);
        if ( n6_1 )
          break;
      }
      AdapterInfo_4 = *(const CHAR **)AdapterInfo_4;
    }
    while ( AdapterInfo_4 );
    p_n6 = n6_1;
    p_C = p_C_1;
    n6_2 = p_n6;
  }
  AdapterInfo_5 = AdapterInfo_2;
  hHeap_2 = GetProcessHeap();
  HeapFree(hHeap_2, 0, AdapterInfo_5);
LABEL_43:
  n19 = 0;
  lpFileName[0] = L"\\\\.\\HGFS";
  lpFileName[1] = L"\\\\.\\vmci";
  if ( !n6_2 )
    n19 = 19;
  n2 = 0;
  n14 = 14;
  p_C[5] = aAbcdefghijlkmn[n19];
  do
  {
    FileW = CreateFileW(lpFileName[n2], 0x80000000, FILE_READ_DATA, 0, OPEN_EXISTING, FILE_READ_ATTRIBUTES, 0);
    if ( FileW != (HANDLE)-1 )
    {
      CloseHandle(FileW);
      ++n14;
    }
    ++n2;
  }
  while ( n2 < 2 );
  n5_1 = 0;
  p_C[6] = aAbcdefghijlkmn[n14];
  v34 = 1;
  psz2[0] = L"vmtoolsd.exe";
  psz2[1] = L"vmwaretray.exe";
  psz2[2] = L"vmwareuser.exe";
  psz2[3] = L"VGAuthService.exe";
  psz2[4] = L"vmacthlp.exe";
  do
  {
    if ( sub_2C16D0(psz2[n5_1]) )
      ++v34;
    ++n5_1;
  }
  while ( n5_1 < 5 );
  p_C[7] = aAbcdefghijlkmn[v34];
  p_n6 = 0;
  n10 = 10;
  v36 = (char *)sub_2C1890(&p_n6);
  if ( v36 )
  {
    v37 = 0;
    if ( p_n6 != 6 )
    {
      while ( *(_DWORD *)&v36[v37] != 'awMV' || *(_WORD *)&v36[v37 + 4] != 'er' )
      {
        if ( ++v37 >= (unsigned int)(p_n6 - 6) )
          goto LABEL_60;
      }
      n10 = 11;
    }
LABEL_60:
    free(v36);
  }
  v38 = aAbcdefghijlkmn[n10];
  n2_1 = 1;
  malloc = ::malloc;
  p_C[8] = v38;
  p_C[9] = 0;
  AdapterInfo_2 = (LPVOID)1;
  cchWideChar_1 = ::malloc(0x1000u);
  cchWideChar = (int)cchWideChar_1;
  if ( cchWideChar_1 )
  {
    n4096 = 4096;
    cchWideChar_2 = cchWideChar_1;
    do
    {
      *cchWideChar_2++ = 0;
      --n4096;
    }
    while ( n4096 );
    n4_3 = sub_2C1810(cchWideChar_2);
    n4_2 = n4_3;
    if ( n4_3 != -1 )
    {
      psz1_3 = (const WCHAR *)(n4_3 >> 2);
      psz1 = psz1_3;
      if ( n4_2 >= 4 && psz1_3 )
      {
        psz1_6 = 0;
        psz1_4 = psz1_3;
        do
        {
          n6 = 0;
          psz1_5 = (const WCHAR *)sub_2C1890(&n6);
          psz1 = psz1_5;
          if ( psz1_5 )
          {
            v50 = sub_2C17D0(psz1_5, n6);
            free((void *)psz1);
            AdapterInfo_6 = (char *)AdapterInfo_2 + 1;
            if ( !v50 )
              AdapterInfo_6 = (char *)AdapterInfo_2;
            n2_1 = (int)AdapterInfo_6;
            AdapterInfo_2 = AdapterInfo_6;
          }
          ++psz1_6;
        }
        while ( psz1_6 < (unsigned int)psz1_4 );
        p_C = p_C_1;
        malloc = ::malloc;
      }
      else
      {
        n2_1 = 2;
      }
      free((void *)cchWideChar);
      if ( n2_1 > 1 )
        ExitProcess(0);
    }
  }
  Buffer_1 = (char *)malloc(0xAu);
  *Buffer_1 = 0;
  for ( k = *p_C; k; ++p_C )
  {
    if ( isalpha(k) )
    {
      v54 = islower(*p_C);
      C = *p_C;
      if ( v54 )
      {
        v56 = (C - 'T') % 26;
        n_a_ = 'a';
        if ( v56 < 0 )
          n_a_ = 0x7B;
        C_1 = v56 + n_a_;
      }
      else
      {
        v59 = (C - '4') % 26;
        n_A_ = 'A';
        if ( v59 < 0 )
          n_A_ = 0x5B;
        C_1 = v59 + n_A_;
      }
    }
    else
    {
      C_1 = *p_C;
    }
    sub_2C13D0(Buffer_1, "%s%c", Buffer_1, C_1);
    k = p_C[1];
  }
  return Buffer_1;
}
```

Tuy khá dài nhưng ta có thể thấy rằng chương trình sẽ có 9 lượt check vm, mỗi lần check vm sẽ map với table tạo thành 1 bytes ký tự của key. Sau khi đủ 9 ký tự thì thực hiện decrypt caesar cipher để tạo thành key cuối cùng cho việc giải mã rc4.

Ta sẽ phải phân tích từng lượt check vm để lấy key chính xác

check 0:

<img width="1317" height="568" alt="image" src="https://github.com/user-attachments/assets/8fe7f869-9ce0-4db2-b414-b1f4a5b95286" />

<img width="1343" height="596" alt="image" src="https://github.com/user-attachments/assets/dcf9cd63-60ba-456e-876d-c34a89cea55b" />


-> khởi tạo `n4 = 4`, mở từng key registry của `VMWARE` , nếu mở thành công sẽ tăng giá trị của `n4` lên 1

Vậy nếu trong môi trường không có vm thì `n4 == 4`

check 1:

<img width="1302" height="252" alt="image" src="https://github.com/user-attachments/assets/b79caef5-9a31-438d-8144-18691c3676a8" />

-> mở key `VMware Tools`, mở thành công thì `n13 = 13`, ngược lại thì 14

Vậy `n13 == 13`

check 2:

<img width="1317" height="457" alt="image" src="https://github.com/user-attachments/assets/661f04d3-f5db-4cb8-8af0-6b4c24cc3c95" />

-> khởi tạo `n15 = 15`, kiểm tra các file driver của VMware, nếu có thì tăng `n15` thêm giá trị

Vậy `n15 == 15`

check 3:

<img width="962" height="202" alt="image" src="https://github.com/user-attachments/assets/3c898250-4c08-4798-9a83-72812abd82ef" />

-> 21

check 4:

<img width="1321" height="361" alt="image" src="https://github.com/user-attachments/assets/0b805ac2-5c98-4d75-ab34-048995f92c29" />

<img width="1318" height="567" alt="image" src="https://github.com/user-attachments/assets/b34c9a04-46fb-4c1b-b526-dbe1eae5342b" />


-> khởi tạo `n13 = 0`, check MAC address VMware, nếu có thì tăng thêm giá trị

Vậy `n13 == 0`

check 5:

<img width="1318" height="572" alt="image" src="https://github.com/user-attachments/assets/5f0f8be7-0ab9-4e67-a220-90b5e7865299" />

-> check các adapter name, nếu không có adapter `VMware` thì `n19 = 19`

Vậy `n19 == 19`

check 6:

<img width="1297" height="366" alt="image" src="https://github.com/user-attachments/assets/b69b3c7e-570f-45b1-aa40-7deff48c8531" />

-> khởi tạo `n14 = 14`, mở các file `HGFS`, `vmci`, nếu thành công thì tăng giá trị của `n14`

Vậy `n14 == 14`

check 7:

<img width="987" height="247" alt="image" src="https://github.com/user-attachments/assets/90de9c70-f3de-4b6d-a01d-5459ca6c94b1" />

-> khởi tạo `v34 = 1`, kiểm tra các process vmware sử dụng, nếu có thì tăng giá trị của `v34`

Vậy `v34 == 1`

check 8:

<img width="992" height="343" alt="image" src="https://github.com/user-attachments/assets/f07329f2-fbcf-4fd3-8e17-7548e28328be" />

-> `n10 == 10`

Từ đó ta viết script lấy key trước khi decrypt caesar cipher:

```python
table=b'ABCDEFGHIJLKMNOPQRSTUVWXYZ'
fake='RACJOGCOY'

riel=''
riel+=chr(table[4])
riel+=chr(table[13])
riel+=chr(table[15])
riel+=chr(table[21])
riel+=chr(table[0])
riel+=chr(table[19])
riel+=chr(table[14])
riel+=chr(table[1])
riel+=chr(table[10])

print(riel)
#ENPVATOBL
```

Lấy key chính xác:

<img width="977" height="581" alt="image" src="https://github.com/user-attachments/assets/0bebf286-585a-4616-8636-aa0b33001e67" />

<img width="1918" height="872" alt="image" src="https://github.com/user-attachments/assets/2c178b8d-bc49-4588-ab55-6dd574099690" />

Decrypt flag:

<img width="1918" height="878" alt="image" src="https://github.com/user-attachments/assets/d36a7537-1d8c-4dad-ae9f-f99bf0b01c6f" />


flag: `vcstraining{Running_in_VM_is_ridiculous}`


## AntiDebug1

<img width="462" height="226" alt="image" src="https://github.com/user-attachments/assets/d599a144-5744-4716-9e99-d7b6e97945bd" />

mở IDA:

<img width="1337" height="492" alt="image" src="https://github.com/user-attachments/assets/e6317c00-e922-4464-88e1-6ae0ad7f7c66" />

Ta thấy antidebug đầu tiên là `SetUnhandledExceptionFilter`, hàm này đăng ký 1 hàm handler, khi exception trigger thì luồng chương trình sẽ nhảy vào hàm handler.

Hàm được đăng ký là `TopLevelExceptionFilter`:

<img width="906" height="503" alt="image" src="https://github.com/user-attachments/assets/df83af5d-3ced-4b67-a2e6-fe5cde6a024f" />


<img width="1913" height="978" alt="image" src="https://github.com/user-attachments/assets/80fd0823-1b41-4c94-b573-d642adcf696c" />

<img width="1346" height="527" alt="image" src="https://github.com/user-attachments/assets/8dd11df3-2874-4d5c-8726-f57526288269" />

Ta thấy exception trigger tại `div eax`, `SetUnhandledExceptionFilter` khác với `AddVectoredExceptionHandler`, nếu dùng debugger và chọn `pass to application` thì sẽ crash chứ không tự nhảy vào hàm đã đăng ký như `AddVectoredExceptionHandler`:

<img width="1085" height="187" alt="image" src="https://github.com/user-attachments/assets/131233ae-661a-4a39-9a4c-e9d85a3969a2" />

Buộc ta phải patch để trực tiếp nhảy vào hàm `TopLevelExceptionFilter` để có thể tiếp tục debug:

<img width="715" height="497" alt="image" src="https://github.com/user-attachments/assets/212969d5-8a63-4940-b51d-35f2091b3738" />

Sau khi patch thì chương trình vẫn hoạt động bình thường:

<img width="611" height="242" alt="image" src="https://github.com/user-attachments/assets/92c19bfb-8522-4ac0-a63f-613751e53102" />

<img width="862" height="265" alt="image" src="https://github.com/user-attachments/assets/a7433123-2623-4429-89c7-359b23b0623e" />

Tiếp tục ta gặp các antidebug là: `IsDebuggerPresent`, `NtGlobalFlag`, `ProcessHeap`:

<img width="1356" height="545" alt="image" src="https://github.com/user-attachments/assets/b832ce42-5e8e-40e3-b839-91c430e004b7" />

Ngoài ra còn có antidebug ở `sub_401757` để chống patch/breakpoint:

<img width="667" height="442" alt="image" src="https://github.com/user-attachments/assets/756f0ae0-f10d-4cb9-a497-7becb8f2f878" />

Ta nop `call sub_401757` và các `jnz` đi để luồng giống với khi không bị debug:

<img width="377" height="642" alt="image" src="https://github.com/user-attachments/assets/68aab295-6c72-4033-b924-d8840e63aff8" />

<img width="472" height="212" alt="image" src="https://github.com/user-attachments/assets/b6be6e3a-e2d6-4098-ba0b-dae56759ddec" />

Tuy nhiên khi ta nhập gì đó vào dialogbox thì chương trình sẽ bị out, ta có thể thấy rằng còn có antidebug ở event nhập input.

Tiếp tục debug:

<img width="1316" height="467" alt="image" src="https://github.com/user-attachments/assets/4586184d-0271-464d-b34c-b0377f9d3ad8" />

Ta thấy chương trình lấy `ProcessDebugPort` bằng `NtQueryInformationProcess`, sau đó thì sử dụng nó để tính toán `v7`, cuối cùng là selfpatch thành nop 0x18 bytes từ `0x40122D`

Ta sẽ patch `v8` sao cho nó luôn = `0x4f`:

<img width="1016" height="242" alt="image" src="https://github.com/user-attachments/assets/33bcfdac-4d48-481e-9b7e-13329650fec6" />

Ta xem tiếp:

<img width="686" height="146" alt="image" src="https://github.com/user-attachments/assets/1f320df4-efc8-43ab-9546-b971b0731c60" />

<img width="685" height="153" alt="image" src="https://github.com/user-attachments/assets/954675c1-3c26-4bf7-b61c-76cb7eb1b21d" />

<img width="792" height="118" alt="image" src="https://github.com/user-attachments/assets/64940ba5-b620-403b-a734-6d34d00e112b" />

<img width="1117" height="470" alt="image" src="https://github.com/user-attachments/assets/dbef381e-4a71-4b4a-a933-f2b5288f0f26" />

Ta thấy antidebug `GetTickCount` tuy nhiên ta tạm thời bỏ qua để đi vào xem hàm `sub_401525` trước:

<img width="1227" height="460" alt="image" src="https://github.com/user-attachments/assets/ef43e9bc-64c4-4607-994a-1434853e6d12" />

Chương trình ẩn thread bằng `NtSetInformationThread`, ta sẽ nop nó đi để có thể tiếp tục debug:

<img width="1487" height="622" alt="image" src="https://github.com/user-attachments/assets/28418744-d310-4710-ac88-e8bde78b93f5" />

ngoài ra còn có hàm chống software breakpoint:

<img width="678" height="348" alt="image" src="https://github.com/user-attachments/assets/74ced122-63f0-4f89-a041-864152765a2f" />

debug tiếp ta thấy:

<img width="1138" height="401" alt="image" src="https://github.com/user-attachments/assets/f2a2a823-1b34-431f-9c20-2a3d02d7f3a9" />

ta sẽ nop phần này đi:

<img width="490" height="486" alt="image" src="https://github.com/user-attachments/assets/b64997e0-9cf6-4fee-b82a-5bf79192ee98" />

tiếp tục:

<img width="1070" height="493" alt="image" src="https://github.com/user-attachments/assets/33a8b9a6-c375-487f-a1c4-e48f728841a3" />

<img width="1327" height="487" alt="image" src="https://github.com/user-attachments/assets/6e9d7fd4-2fa8-4559-8ae5-3f1b49020fe0" />

<img width="426" height="41" alt="image" src="https://github.com/user-attachments/assets/cf5a9ca1-d83f-4786-be4a-ebe9ceb884b0" />

Chương trình lấy snapshot các process và tìm process có tên `csrss.exe`.

tiếp tục:

<img width="617" height="201" alt="image" src="https://github.com/user-attachments/assets/50ce5409-2970-4c95-884f-7fa9805442f7" />

<img width="787" height="465" alt="image" src="https://github.com/user-attachments/assets/cdc40683-d5c2-4b6a-83c4-f56d29e09210" />

<img width="1277" height="507" alt="image" src="https://github.com/user-attachments/assets/0156c035-d50d-4dfb-9064-2619bfaf3e08" />

Chương trình lấy path của chính nó và tìm xem có process nào khác chứa tên nó không

Tiếp tục vẫn là tìm các process để kiểm tra debugger:

<img width="582" height="92" alt="image" src="https://github.com/user-attachments/assets/9e66f198-8a1a-4f8b-978a-f67a29ea82f7" />

Tiếp tục debug ta thấy antidebug dùng `GetTickCount`:

<img width="867" height="446" alt="image" src="https://github.com/user-attachments/assets/9b269c50-5839-48bd-a46e-c8452fb15af3" />

Ta chỉ cần sửa `jbe` thành `jmp` để đi vào luồng đúng.

debug tiếp:

<img width="1272" height="318" alt="image" src="https://github.com/user-attachments/assets/4ce3649f-94a7-4336-8ccc-e35297be9fef" />

<img width="1207" height="358" alt="image" src="https://github.com/user-attachments/assets/1753f09d-d368-419a-96b8-d0603dad902a" />

Đây chính là chỗ kiểm tra input ta nhập vào và password đích.

Vậy ta đã có password đầy đủ là:

`NtQu3ry1nf0rm@t10nPr0(355R@!s33xc3pt!onD3bugPr1v1l3g3St@ckT1m3CCS3lf-P3BF1ndW1nd0wH1d1ng@nt1-R3v3rs3`

Nhập vào DialogBox:

<img width="458" height="203" alt="image" src="https://github.com/user-attachments/assets/3970a47c-38d9-41bf-86aa-6607113325d9" />

flag: `NtQu3ry1nf0rm@t10nPr0(355R@!s33xc3pt!onD3bugPr1v1l3g3St@ckT1m3CCS3lf-P3BF1ndW1nd0wH1d1ng@nt1-R3v3rs3`


## Simple Anti Debug

<img width="584" height="281" alt="image" src="https://github.com/user-attachments/assets/3c0944a2-23ea-496f-bba3-5111c32e7e40" />

<img width="1416" height="714" alt="image" src="https://github.com/user-attachments/assets/ec7608b0-a3e9-4dfb-a6c1-ca6be331d728" />

Ta phát hiện `TlsCallback`:

<img width="1343" height="466" alt="image" src="https://github.com/user-attachments/assets/067e2f18-312b-4536-8283-c88e6e6a104a" />

chương trình sử dụng kỹ thuật API hashing để resolve api 

ta đặt có thể debug để xem chương trình gọi API gì:

<img width="663" height="51" alt="image" src="https://github.com/user-attachments/assets/ef1f0858-565d-4961-bfe2-1a19651aec1d" />

chương trình lấy `ProcessDebugPort` để antidebug

Ta sẽ patch `v6 = 0` để chương trình vào luồng đúng:

<img width="520" height="533" alt="image" src="https://github.com/user-attachments/assets/1d1db6c7-2d94-45c2-b4ec-cd9e597c5e17" />

<img width="617" height="182" alt="image" src="https://github.com/user-attachments/assets/74173496-2172-48f4-a8d2-d0f516107814" />




Event nhận input:

<img width="1290" height="616" alt="image" src="https://github.com/user-attachments/assets/c50041af-8b06-4b00-8cca-d1b41e61bcea" />

Check input:

<img width="1339" height="588" alt="image" src="https://github.com/user-attachments/assets/81dffa3f-a5ac-4772-b19b-ef80f95d63c2" />

Chương trình yêu cầu input phải dài `0x26` ký tự

Ta đi phân tích từng case antidebug:

case 6:

<img width="731" height="91" alt="image" src="https://github.com/user-attachments/assets/29500728-192e-47da-9e05-23c6f0e60be9" />

<img width="1341" height="588" alt="image" src="https://github.com/user-attachments/assets/fda0b1be-89f7-466f-9ccb-1d6ac6584152" />


<img width="886" height="85" alt="image" src="https://github.com/user-attachments/assets/3c58f245-cb7a-47e2-b794-822d2a449514" />

Chương trình gọi `NtUserBlockInput` 2 lần, trong điều kiện bình thường, chương trình sẽ chỉ block input 1 lần, lần sau sẽ bị trả về false

Patch để luôn vào label 3:

<img width="633" height="235" alt="image" src="https://github.com/user-attachments/assets/49ce5a20-0c45-4c9b-99ed-182d7aae3310" />

<img width="837" height="353" alt="image" src="https://github.com/user-attachments/assets/b446991e-4b72-46d2-85f5-0f9fa79dbe91" />


case 1:

<img width="1315" height="198" alt="image" src="https://github.com/user-attachments/assets/2b1bfb9e-a0e9-48c8-8f68-b177e1b29bff" />

<img width="1317" height="576" alt="image" src="https://github.com/user-attachments/assets/616ea293-5dfc-4b57-9aa8-a8120f8e17dc" />

Chương trình antidebug bằng `NtGlobalFlag`, khi process được khởi tạo bằng debugger thì dẫn đến `NtGlobalFlag == 0x70` còn khi bình thường hoặc kể cả khi debugger attach vào thì giá trị này luôn bằng 0

Vậy ta sẽ phải patch để `n112` luôn bằng 0:

<img width="908" height="268" alt="image" src="https://github.com/user-attachments/assets/337084c7-7f38-4c2c-aef3-98dbbd187287" />

<img width="651" height="193" alt="image" src="https://github.com/user-attachments/assets/e5232920-b44e-408a-898a-27c31b698fa8" />

case 7: 

<img width="1320" height="380" alt="image" src="https://github.com/user-attachments/assets/af6c849d-93bf-468d-8945-eae4e62d6cee" />

<img width="707" height="67" alt="image" src="https://github.com/user-attachments/assets/b676a163-70fe-46ec-a85d-17a5fa0b3416" />

case này antidebug bằng `ProcessDebugFlags`

patch:

<img width="622" height="468" alt="image" src="https://github.com/user-attachments/assets/00b4a482-1fdc-4a30-aa66-fcff5aad1535" />

<img width="846" height="256" alt="image" src="https://github.com/user-attachments/assets/44fff46c-fca5-4993-a876-ddc68e97f75f" />

case 3:

<img width="907" height="52" alt="image" src="https://github.com/user-attachments/assets/2d4d94e0-be22-47cf-b3d9-59478bacd582" />

<img width="1160" height="391" alt="image" src="https://github.com/user-attachments/assets/57ec90b2-ed04-4e62-ac52-ef317a8c1e7e" />

patch:

<img width="1097" height="418" alt="image" src="https://github.com/user-attachments/assets/42e07ff9-ece3-492d-b6f0-4fe19e1bab28" />

<img width="822" height="210" alt="image" src="https://github.com/user-attachments/assets/60a5c135-619a-4709-8039-bb4c2a4a5ce9" />


case 2:

<img width="720" height="62" alt="image" src="https://github.com/user-attachments/assets/69176c31-e746-4d25-9d5b-6b36f24fcaab" />

<img width="1291" height="487" alt="image" src="https://github.com/user-attachments/assets/220ca2dd-764b-4e45-9db1-34d3cf22eede" />

tương tự như case 3 và tắt block input

patch:

<img width="645" height="427" alt="image" src="https://github.com/user-attachments/assets/a39ab056-7a12-45be-99ee-f5d3364183b6" />


case 4:

<img width="676" height="56" alt="image" src="https://github.com/user-attachments/assets/a3211d8f-f4b4-44eb-a3f8-ac79a65e08c9" />

<img width="1315" height="572" alt="image" src="https://github.com/user-attachments/assets/880ab9a1-2782-4afb-be35-1f64f13535e1" />

cơ chế antidebug: nếu HEAP_TAIL_CHECKING_ENABLED flag được bật thì 0xABABABAB sẽ được thêm vào cuối khối heap đã cấp phát

<img width="1918" height="587" alt="image" src="https://github.com/user-attachments/assets/1ff98f3f-2376-42b9-a36f-74cdcbd89366" />

patch:

<img width="788" height="560" alt="image" src="https://github.com/user-attachments/assets/55d035a0-3be3-46d7-a1db-8252a3e5da51" />

<img width="1027" height="442" alt="image" src="https://github.com/user-attachments/assets/c1af5fda-839c-4d2d-bb71-fd657e74db6d" />

case 5:

<img width="755" height="56" alt="image" src="https://github.com/user-attachments/assets/48e8dd0f-0cb3-45d4-8622-8c5c0c8acf41" />

<img width="1320" height="571" alt="image" src="https://github.com/user-attachments/assets/9c5040d8-b53d-444a-b288-8e4032789041" />

đã bypass hết các antidebug, ta chỉ cần nhặt các flag theo thứ tự là được.

I_10v3-y0U__wh3n Y0u=c411..M3 Senor1t4

<img width="1402" height="712" alt="image" src="https://github.com/user-attachments/assets/88cd56bd-0f9b-4c4c-9e7b-912f415c61f5" />

flag: `vcstraining{Th3_U1tiM4t3_ant1_D3Bu9_ref3r3ncE}`






