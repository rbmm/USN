#include "stdafx.h"
#include "resource.h"
_NT_BEGIN
#include <mountmgr.h>
#include "../inc/ntfs structs.h"

extern const volatile UCHAR guz = 0;

class WLog
{
	PVOID _BaseAddress;
	ULONG _RegionSize, _Ptr;

	PWSTR _buf()
	{
		return (PWSTR)((PBYTE)_BaseAddress + _Ptr);
	}

	ULONG _cch()
	{
		return (_RegionSize - _Ptr) / sizeof(WCHAR);
	}

public:

	void operator >> (HWND hwnd)
	{
		PVOID pv = (PVOID)SendMessage(hwnd, EM_GETHANDLE, 0, 0);
		SendMessage(hwnd, EM_SETHANDLE, (WPARAM)_BaseAddress, 0);
		_BaseAddress = 0;
		if (pv)
		{
			LocalFree(pv);
		}
	}

	ULONG Init(SIZE_T RegionSize)
	{
		if (_BaseAddress = LocalAlloc(0, RegionSize))
		{
			_RegionSize = (ULONG)RegionSize, _Ptr = 0;
			return NOERROR;
		}
		return GetLastError();
	}

	~WLog()
	{
		if (_BaseAddress)
		{
			LocalFree(_BaseAddress);
		}
	}

	WLog(WLog&&) = delete;
	WLog(WLog&) = delete;
	WLog() : _BaseAddress(0) {}

	operator PCWSTR()
	{
		return (PCWSTR)_BaseAddress;
	}

	WLog& operator ()(PCWSTR format, ...)
	{
		va_list args;
		va_start(args, format);

		int len = _vsnwprintf_s(_buf(), _cch(), _TRUNCATE, format, args);

		if (0 < len)
		{
			_Ptr += len * sizeof(WCHAR);
		}

		va_end(args);

		return *this;
	}

	WLog& operator[](HRESULT dwError)
	{
		LPCVOID lpSource = 0;
		ULONG dwFlags = FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS;

		if (dwError & FACILITY_NT_BIT)
		{
			dwError &= ~FACILITY_NT_BIT;
			dwFlags = FORMAT_MESSAGE_FROM_HMODULE|FORMAT_MESSAGE_IGNORE_INSERTS;

			static HMODULE ghnt;
			if (!ghnt && !(ghnt = GetModuleHandle(L"ntdll"))) return *this;
			lpSource = ghnt;
		}

		if (dwFlags = FormatMessageW(dwFlags, lpSource, dwError, 0, _buf(), _cch(), 0))
		{
			_Ptr += dwFlags * sizeof(WCHAR);
		}
		return *this;
	}
};

//////////////////////////////////////////////////////////////////////////
struct MFT_OUT_DATA
{
	USN Usn;
	USN_RECORD_UNION ur;
};

struct VOLUME_USN
{
	ULONGLONG UsnJournalID;
	HANDLE hVolume;

	VOLUME_USN(VOLUME_USN& from) : hVolume(from.hVolume), UsnJournalID(from.UsnJournalID)
	{
		from.hVolume = 0;
	}

	VOLUME_USN(HANDLE hVolume) : hVolume(hVolume) {}

	~VOLUME_USN()
	{
		if (hVolume)
		{
			NtClose(hVolume);
		}
	}
};

struct QueryData 
{
	ULONGLONG UsnJournalID;
	ULONG ReasonMask;
	ULONG FileCount;
	ULONG dwTotalBytes;
};

NTSTATUS DoQuery(HANDLE hVolume, LONGLONG Bias, ULONGLONG MinTimeStamp, ULONGLONG MaxTimeStamp, 
				 QueryData* pqd, MFT_OUT_DATA *pmod, ULONG cbBuf, USN Usn[], ULONG UsnCount)
{
	MaxTimeStamp -= MinTimeStamp;

	ULONG Count = 0, dwTotal = 0;

	READ_USN_JOURNAL_DATA_V1 ReadData = { 0, pqd->ReasonMask, FALSE, 0, 0, pqd->UsnJournalID, 2, 2 };

	ULONGLONG FileReferenceNumber = 0;
	NTSTATUS status;
	IO_STATUS_BLOCK iosb;

	while(0 <= (status = NtFsControlFile(hVolume, 0, 0, 0, &iosb, 
		FSCTL_READ_USN_JOURNAL, &ReadData, sizeof(ReadData), pmod, cbBuf)))
	{
		if (iosb.Information >= sizeof(USN))
		{
			ReadData.StartUsn = pmod->Usn;

			if (iosb.Information -= sizeof(USN))
			{
				dwTotal += iosb.Information;

				union {
					PBYTE pb;
					PUSN_RECORD_UNION pur;
				};

				pur = &pmod->ur;

				ULONG RecordLength;

				do 
				{
					RecordLength = pur->Header.RecordLength;

					switch (pur->Header.MajorVersion)
					{
					case 2:
						if (FileReferenceNumber == pur->V2.FileReferenceNumber)
						{
							continue;
						}

						FileReferenceNumber = pur->V2.FileReferenceNumber;

						ULONG Reason = pur->V2.Reason;

						if (
							((Reason & USN_REASON_FILE_CREATE) && !(ReadData.ReasonMask & USN_REASON_FILE_CREATE))
							||
							((Reason & USN_REASON_FILE_DELETE) && !(ReadData.ReasonMask & USN_REASON_FILE_DELETE))
							)
						{
							continue;
						}

						if ((ULONGLONG)((pur->V2.TimeStamp.QuadPart -= Bias) - MinTimeStamp) <= MaxTimeStamp)
						{
							Usn[Count++ % UsnCount] = pur->V2.Usn;
						}
						break;
					}

				} while (pb += RecordLength, iosb.Information -= RecordLength);
			}
			else
			{
				break;
			}
		}
	}

	pqd->FileCount = Count, pqd->dwTotalBytes = dwTotal;

	return status;
}

NTSTATUS DoQuery(WLog& log, HANDLE hVolume, LONGLONG Bias, ULONGLONG MinTimeStamp, ULONGLONG MaxTimeStamp, 
				 QueryData* pqd, MFT_OUT_DATA *pmod, ULONG cbBuf, USN StartUsn)
{
	MaxTimeStamp -= MinTimeStamp;

	ULONG Count = 0, dwBytes;

	READ_USN_JOURNAL_DATA_V1 ReadData = { StartUsn, pqd->ReasonMask, FALSE, 0, 0, pqd->UsnJournalID, 2, 2 };

	NTSTATUS status;
	IO_STATUS_BLOCK iosb;

	bool fniValid = false;
	PFILE_NAME_INFORMATION pfni = (PFILE_NAME_INFORMATION)RtlOffsetToPointer(pmod, cbBuf);

	ULONGLONG ParentFileReferenceNumber = 0, FileReferenceNumber = 0;
	UNICODE_STRING ObjectName = { 
		sizeof(ParentFileReferenceNumber), sizeof(ParentFileReferenceNumber), (PWSTR)&ParentFileReferenceNumber 
	};
	OBJECT_ATTRIBUTES oa = { sizeof(oa), hVolume, &ObjectName };

	while(0 <= (status = NtFsControlFile(hVolume, 0, 0, 0, &iosb, 
		FSCTL_READ_USN_JOURNAL, &ReadData, sizeof(ReadData), pmod, cbBuf)))
	{
		if ((dwBytes = (ULONG)iosb.Information) >= sizeof(USN))
		{
			ReadData.StartUsn = pmod->Usn;

			if (!(dwBytes -= sizeof(USN)))
			{
				break;
			}

			union {
				PBYTE pb;
				PUSN_RECORD_UNION pur;
			};

			pur = &pmod->ur;

			ULONG RecordLength;

			do 
			{
				RecordLength = pur->Header.RecordLength;

				USHORT FileNameLength = 0;
				PWSTR FileName = 0;

				switch (pur->Header.MajorVersion)
				{
				case 2:
					if (FileReferenceNumber == pur->V2.FileReferenceNumber)
					{
						continue;
					}

					FileReferenceNumber = pur->V2.FileReferenceNumber;

					ULONG Reason = pur->V2.Reason;
					
					if (
						((Reason & USN_REASON_FILE_CREATE) && !(ReadData.ReasonMask & USN_REASON_FILE_CREATE))
						||
						((Reason & USN_REASON_FILE_DELETE) && !(ReadData.ReasonMask & USN_REASON_FILE_DELETE))
						)
					{
						continue;
					}

					FileName = pur->V2.FileName;
					FileNameLength = pur->V2.FileNameLength >> 1;

					if ((ULONGLONG)((pur->V2.TimeStamp.QuadPart -= Bias) - MinTimeStamp) <= MaxTimeStamp)
					{
						Count++;

						TIME_FIELDS tf;

						RtlTimeToTimeFields((PLARGE_INTEGER)&pur->V2.TimeStamp, &tf);
						log(L"%u-%02u-%02u %02u:%02u:%02u [%08x] [%016I64x] | ",
							tf.Year, tf.Month, tf.Day, tf.Hour, tf.Minute, tf.Second,
							Reason, FileReferenceNumber);

						if (ParentFileReferenceNumber != pur->V2.ParentFileReferenceNumber)
						{
							ParentFileReferenceNumber = pur->V2.ParentFileReferenceNumber;
							fniValid = false;
							HANDLE hFile;
							
							if (0 <= NtOpenFile(&hFile, FILE_READ_ATTRIBUTES, &oa, 
								&iosb, FILE_SHARE_VALID_FLAGS, FILE_OPEN_BY_FILE_ID|FILE_DIRECTORY_FILE))
							{
								fniValid = 0 <= NtQueryInformationFile(hFile, &iosb, pfni, 0x10000, FileNameInformation);
								NtClose(hFile);
							}
						}

						if (fniValid)
						{
							log(L"%.*s", pfni->FileNameLength >> 1, pfni->FileName);
						}
						else
						{
							log(L"<%016I64x>", ParentFileReferenceNumber);
						}

						log(L"\\%.*s\r\n", FileNameLength, FileName);
					}
					break;
				}

			} while (pb += RecordLength, dwBytes -= RecordLength);
		}
	}

	if (0 > status)
	{
		log[HRESULT_FROM_NT(status)];
	}

	pqd->FileCount = Count;

	return status;
}

//////////////////////////////////////////////////////////////////////////
class SDialog
{
	LONGLONG _Bias = 0;
	MFT_OUT_DATA* _pmod = 0;
	HFONT _hFont = 0;
	HICON _hi[2]{};
	ULONG _Count = 0;
	LONG _Index = -1;

	enum { sizeOutBuf = 0x100000 };

	INT_PTR OnInitDialog(HWND hwndDlg);

	void OnOk(HWND hwndDlg);
	void OnDestroy(HWND hwndDlg);

	INT_PTR DialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

	static INT_PTR CALLBACK _DialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
	{
		return reinterpret_cast<SDialog*>(GetWindowLongPtrW(hwndDlg, DWLP_USER))->DialogProc(hwndDlg, uMsg, wParam, lParam);
	}

	static INT_PTR CALLBACK StartDialogProc(HWND hwndDlg, UINT uMsg, WPARAM /*wParam*/, LPARAM lParam)
	{
		if (uMsg == WM_INITDIALOG)
		{
			SetWindowLongPtrW(hwndDlg, DWLP_USER, lParam);
			SetWindowLongPtrW(hwndDlg, DWLP_DLGPROC, (LONG_PTR)_DialogProc);
			return reinterpret_cast<SDialog*>(lParam)->OnInitDialog(hwndDlg);
		}

		return 0;
	}

	static NTSTATUS AddVolume(HWND hwndCombo, HANDLE hMM, VOLUME_USN& rvu);
	void ResetContent(HWND hwndCombo);
	void EnumVolumes(HWND hwndCombo);
public:

	INT_PTR DoModal()
	{
		return DialogBoxParamW((HINSTANCE)&__ImageBase, MAKEINTRESOURCEW(IDD_DIALOG2), HWND_DESKTOP, StartDialogProc, (LPARAM)this);
	}
};

void SDialog::OnDestroy(HWND hwndDlg)
{
	ResetContent(GetDlgItem(hwndDlg, IDC_COMBO1));

	if (_pmod)
	{
		VirtualFree(_pmod, 0, MEM_RELEASE);
	}

	if (_hFont)
	{
		DeleteObject(_hFont);
	}

	int i = _countof(_hi);
	do 
	{
		if (HICON hi = _hi[--i])
		{
			DestroyIcon(hi);
		}
	} while (i);
}

INT_PTR SDialog::OnInitDialog(HWND hwndDlg)
{
	static const int 
		X_index[] = { SM_CXSMICON, SM_CXICON }, 
		Y_index[] = { SM_CYSMICON, SM_CYICON },
		icon_type[] = { ICON_SMALL, ICON_BIG};

	ULONG i = _countof(icon_type) - 1;
	do 
	{
		HICON hi;

		if (0 <= LoadIconWithScaleDown((HINSTANCE)&__ImageBase, MAKEINTRESOURCE(IDI_ICON1), 
			GetSystemMetrics(X_index[i]), GetSystemMetrics(Y_index[i]), &hi))
		{
			_hi[i] = hi;
			SendMessage(hwndDlg, WM_SETICON, icon_type[i], (LPARAM)hi);
		}
	} while (i--);

	NONCLIENTMETRICS ncm = { sizeof(NONCLIENTMETRICS) };
	if (SystemParametersInfo(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0))
	{
		wcscpy(ncm.lfMessageFont.lfFaceName, L"Courier New");
		ncm.lfMessageFont.lfHeight = -ncm.iMenuHeight;
		ncm.lfMessageFont.lfWeight = FW_NORMAL;
		ncm.lfMessageFont.lfQuality = CLEARTYPE_QUALITY;
		ncm.lfMessageFont.lfPitchAndFamily = FIXED_PITCH|FF_MODERN;
		ncm.lfMessageFont.lfHeight = -ncm.iMenuHeight;

		_hFont = CreateFontIndirect(&ncm.lfMessageFont);
	}

	if (MFT_OUT_DATA *pmod = (MFT_OUT_DATA*)VirtualAlloc(NULL, sizeOutBuf + 0x10000, MEM_COMMIT, PAGE_READWRITE))
	{
		_pmod = pmod;

		SYSTEM_TIMEOFDAY_INFORMATION sti;
		if (0 <= NtQuerySystemInformation(SystemTimeOfDayInformation, &sti, sizeof(sti), 0))
		{
			_Bias = sti.TimeZoneBias.QuadPart;
		}

		SetDlgItemTextW(hwndDlg, IDC_EDIT2, L"256");
		CheckDlgButton(hwndDlg, IDC_CHECK3, BST_CHECKED);
		EnumVolumes(GetDlgItem(hwndDlg, IDC_COMBO1));

		SYSTEMTIME st;

		GetSystemTime(&st);

		struct L 
		{
			static void Set(HWND hwnd, ULONG id, PSYSTEMTIME pst)
			{
				DateTime_SetSystemtime(hwnd = GetDlgItem(hwnd, id), GDT_VALID, pst);
				DateTime_SetSystemtime(hwnd, GDT_NONE, 0);
			}
		};

		st.wHour = 0, st.wMinute = 0, st.wSecond = 0, st.wMilliseconds = 0;
		L::Set(hwndDlg, IDC_DATETIMEPICKER1, &st);
		L::Set(hwndDlg, IDC_DATETIMEPICKER2, &st);
		L::Set(hwndDlg, IDC_DATETIMEPICKER4, &st);
		st.wHour = 23, st.wMinute = 59, st.wSecond = 59, st.wMilliseconds = 999;
		L::Set(hwndDlg, IDC_DATETIMEPICKER3, &st);

		SetFocus(0);
		return 0;
	}

	EndDialog(hwndDlg, -1);
	return 0;
}

void SDialog::OnOk(HWND hwndDlg)
{
	VOLUME_USN* pvu = (VOLUME_USN*)ComboBox_GetItemData(GetDlgItem(hwndDlg, IDC_COMBO1), _Index);

	if (!pvu)
	{
		return;
	}
	
	QueryData qd = { pvu->UsnJournalID };

	BOOL b;
	ULONG UsnCount = GetDlgItemInt(hwndDlg, IDC_EDIT2, &b, FALSE);
	if (!b || UsnCount - 1 > 1024)
	{
		MessageBoxW(hwndDlg, L"must be in range [1.. 1024]", L"invalid max recored count !", MB_ICONHAND);
		return;
	}

	static const ULONG Reasons[] = {
		USN_REASON_FILE_DELETE, 
		USN_REASON_FILE_CREATE, 
		USN_REASON_RENAME_NEW_NAME,
		USN_REASON_RENAME_OLD_NAME,
		USN_REASON_STREAM_CHANGE,
		USN_REASON_BASIC_INFO_CHANGE,
		USN_REASON_DATA_OVERWRITE,
		USN_REASON_DATA_TRUNCATION,
		USN_REASON_EA_CHANGE
	};

	static const ULONG nID[] = {
		IDC_CHECK3, 
		IDC_CHECK4, 
		IDC_CHECK5, 
		IDC_CHECK6, 
		IDC_CHECK7, 
		IDC_CHECK8, 
		IDC_CHECK9, 
		IDC_CHECK10, 
		IDC_CHECK11, 
	};

	C_ASSERT(_countof(nID) == _countof(Reasons));

	ULONG i = _countof(nID);
	do 
	{
		if (IsDlgButtonChecked(hwndDlg, nID[--i]))
		{
			qd.ReasonMask |= Reasons[i];
		}
	} while (i);

	if (!qd.ReasonMask)
	{
		MessageBoxW(hwndDlg, 0, L"one or more reasons must be selected !", MB_ICONHAND);
		return ;
	}

	ULONGLONG MinTimeStamp = 0, MaxTimeStamp = MAXLONGLONG;

	struct L 
	{
		static void get(HWND hwndDlg, ULONG idData, ULONG idTime, PULONGLONG time)
		{
			SYSTEMTIME st, st2;
			if (DateTime_GetSystemtime(GetDlgItem(hwndDlg, idData), &st) == GDT_VALID)
			{
				if (DateTime_GetSystemtime(GetDlgItem(hwndDlg, idTime), &st2) == GDT_VALID)
				{
					st.wHour = st2.wHour, st.wMinute = st2.wMinute, st.wSecond = st2.wSecond;
				}

				SystemTimeToFileTime(&st, (PFILETIME)time);
			}
		}
	};

	L::get(hwndDlg, IDC_DATETIMEPICKER2, IDC_DATETIMEPICKER1, &MinTimeStamp);
	L::get(hwndDlg, IDC_DATETIMEPICKER4, IDC_DATETIMEPICKER3, &MaxTimeStamp);

	if (MaxTimeStamp <= MinTimeStamp)
	{
		MessageBoxW(hwndDlg, L"from must be < to", L"invalid period !", MB_ICONHAND);
		return ;
	}

	if (USN* Usn = new USN[UsnCount])
	{
		DoQuery(pvu->hVolume, _Bias, MinTimeStamp, MaxTimeStamp, &qd, _pmod, sizeOutBuf, Usn, UsnCount);

		if (qd.FileCount)
		{
			WLog log;

			if (!log.Init(0x80000))
			{
				DoQuery(log, pvu->hVolume, _Bias, MinTimeStamp, MaxTimeStamp, &qd, _pmod, sizeOutBuf, 
					Usn[qd.FileCount < UsnCount ? 0 : qd.FileCount % UsnCount]);
				
				WCHAR szVolume[0x100];
				GetDlgItemTextW(hwndDlg, IDC_COMBO1, szVolume, _countof(szVolume));

				if (HWND hwnd = CreateWindowExW(0, WC_EDIT, szVolume, 
					WS_OVERLAPPEDWINDOW|WS_HSCROLL|WS_VSCROLL|ES_MULTILINE,
					CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, hwndDlg, 0, 0, 0))
				{
					if (_hFont) SendMessage(hwnd, WM_SETFONT, (WPARAM)_hFont, 0);

					ULONG n = 8;
					SendMessage(hwnd, EM_SETTABSTOPS, 1, (LPARAM)&n);
					
					log >> hwnd;

					SendMessage(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)_hi[0]);
					SendMessage(hwnd, WM_SETICON, ICON_BIG, (LPARAM)_hi[1]);

					ShowWindow(hwnd, SW_SHOWNORMAL);
				}
			}
		}
		else
		{
			MessageBoxW(hwndDlg, 0, L"no records find", MB_ICONWARNING);
		}

		delete [] Usn;
	}
}

NTSTATUS SDialog::AddVolume(HWND hwndCombo, HANDLE hMM, VOLUME_USN& rvu)
{
	union {
		PVOID buf;
		PMOUNTDEV_NAME pmdn;
	};

	NTSTATUS status;
	IO_STATUS_BLOCK iosb;

	PVOID stack = alloca(guz);
	ULONG cb = 0, rcb = sizeof(MOUNTDEV_NAME) + 0x80, InputBufferLength;
	do 
	{
		if (cb < rcb)
		{
			cb = RtlPointerToOffset(buf = alloca(rcb - cb), stack);
		}

		if (0 <= (status = NtDeviceIoControlFile(rvu.hVolume, 0, 0, 0, 
			&iosb, IOCTL_MOUNTDEV_QUERY_DEVICE_NAME, 0, 0, buf, cb)))
		{
			union {
				PVOID pv;
				PMOUNTMGR_VOLUME_PATHS pmvp;
			};

			cb = 0, rcb = sizeof(MOUNTMGR_VOLUME_PATHS) + 0x80, InputBufferLength = sizeof(MOUNTDEV_NAME) + pmdn->NameLength;

			do 
			{
				if (cb < rcb)
				{
					cb = RtlPointerToOffset(pv = alloca(rcb - cb), pmdn);
				}

				if (0 <= (status = NtDeviceIoControlFile(hMM, 0, 0, 0, &iosb, 
					IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATH, pmdn, InputBufferLength, pmvp, cb)))
				{
					int i = ComboBox_AddString(hwndCombo, pmvp->MultiSz);

					if (0 <= i)
					{
						if (VOLUME_USN* pvu = new VOLUME_USN(rvu))
						{
							if (0 <= ComboBox_SetItemData(hwndCombo, i, pvu))
							{
								return STATUS_SUCCESS;
							}

							delete pvu;
						}

						ComboBox_DeleteString(hwndCombo, i);
					}

					return STATUS_NO_MEMORY;
				}

				rcb = sizeof(MOUNTMGR_VOLUME_PATHS) + pmvp->MultiSzLength;

			} while (status == STATUS_BUFFER_OVERFLOW);

			break;
		}

		rcb = sizeof(MOUNTDEV_NAME) + pmdn->NameLength;

	} while (status == STATUS_BUFFER_OVERFLOW);

	return status;
}

void SDialog::ResetContent(HWND hwndCombo)
{
	if (ULONG n = _Count)
	{
		do 
		{
			if (VOLUME_USN* pvu = (VOLUME_USN*)ComboBox_GetItemData(hwndCombo, --n))
			{
				delete pvu;
			}
		} while (n);
		ComboBox_ResetContent(hwndCombo);
		_Count = 0;
	}
}

void SDialog::EnumVolumes(HWND hwndCombo)
{
	ResetContent(hwndCombo);
	CONFIGRET err;

	PVOID stack = alloca(guz);
	ULONG BufferLen = 0, NeedLen = 0x800;

	union {
		PVOID buf;
		PWSTR pszDeviceInterface;
	};

	for(;;) 
	{
		if (BufferLen < NeedLen)
		{
			BufferLen = RtlPointerToOffset(buf = alloca((NeedLen - BufferLen) * sizeof(WCHAR)), stack) / sizeof(WCHAR);
		}

		switch (err = CM_Get_Device_Interface_ListW(const_cast<PGUID>(&GUID_DEVINTERFACE_VOLUME), 
			0, pszDeviceInterface, BufferLen, CM_GET_DEVICE_INTERFACE_LIST_PRESENT))
		{
		case CR_BUFFER_SMALL:
			if (err = CM_Get_Device_Interface_List_SizeW(&NeedLen, const_cast<PGUID>(&GUID_DEVINTERFACE_VOLUME), 
				0, CM_GET_DEVICE_INTERFACE_LIST_PRESENT))
			{
		default:
			return ;
			}
			continue;

		case CR_SUCCESS:

			HANDLE hMM = CreateFileW(MOUNTMGR_DOS_DEVICE_NAME, FILE_GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0);

			if (hMM != INVALID_HANDLE_VALUE)
			{
				while (*pszDeviceInterface)
				{
					HANDLE hFile = CreateFileW(pszDeviceInterface, FILE_GENERIC_READ, 
						FILE_SHARE_VALID_FLAGS, 0, OPEN_EXISTING, 0, 0);

					if (hFile != INVALID_HANDLE_VALUE)
					{
						VOLUME_USN vu(hFile);

						IO_STATUS_BLOCK iosb;

						USN_JOURNAL_DATA_V1 ujd;

						if (0 <= NtFsControlFile(hFile, 0, 0, 0, &iosb, 
							FSCTL_QUERY_USN_JOURNAL, 0, 0, &ujd, sizeof(ujd)))
						{
							vu.UsnJournalID = ujd.UsnJournalID;

							if (0 <= AddVolume(hwndCombo, hMM, vu))
							{
								_Count++;
							}
						}
					}

					pszDeviceInterface += 1 + wcslen(pszDeviceInterface);
				}

				NtClose(hMM);
			}

			return ;
		}
	}
}

INT_PTR SDialog::DialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_DESTROY:
		OnDestroy(hwndDlg);
		break;
	case WM_COMMAND:
		switch (wParam)
		{
		case MAKEWPARAM(IDOK, BN_CLICKED):
			OnOk(hwndDlg);
			break;
		case IDCANCEL:
			EndDialog(hwndDlg, 0);
			break;
		case MAKEWPARAM(IDC_COMBO1, CBN_CLOSEUP):
			lParam = SendMessageW((HWND)lParam, CB_GETCURSEL, 0, 0);
			_Index = (ULONG)lParam;
			EnableWindow(GetDlgItem(hwndDlg, IDOK), 0 <= lParam);
			EnableWindow(GetDlgItem(hwndDlg, IDC_BUTTON1), 0 <= lParam);
			SetFocus(0);
			break;
		case MAKEWPARAM(IDC_BUTTON2, BN_CLICKED):
			EnumVolumes(GetDlgItem(hwndDlg, IDC_COMBO1));
			break;
		}
		break;
	case WM_NOTIFY:
		switch (wParam)
		{
		case IDC_DATETIMEPICKER2:
		case IDC_DATETIMEPICKER3:
			if (reinterpret_cast<NMHDR*>(lParam)->code == DTN_DATETIMECHANGE)
			{
				if (reinterpret_cast<NMDATETIMECHANGE*>(lParam)->dwFlags == GDT_NONE)
				{
					DateTime_SetSystemtime(GetDlgItem(hwndDlg, (ULONG)wParam - 1), GDT_NONE, 0);
				}
			}
			break;
		}
		;
		break;
	}
	return 0;
}

void WINAPI ep(void*)
{
	{
		SDialog dlg;
		dlg.DoModal();
	}

	ExitProcess(0);
}

#include <initguid.h>
#include <ntddstor.h>
 
_NT_END