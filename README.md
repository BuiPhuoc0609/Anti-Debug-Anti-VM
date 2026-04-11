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
