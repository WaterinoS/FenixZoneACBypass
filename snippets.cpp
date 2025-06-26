#define SIG_FENIXZONE_COMM					"55 89 E5 57 56 53 83 EC 4C 8B 75 08 C7 44 24 ? ? ? ? ? C7 44 24 ? ? ? ? ? C7 04 24 ? ? ? ? FF 15 ? ? ? ? 89 C3"
#define SIG_FENIXZONE_CLOSE					"55 89 E5 83 EC 18 C7 05 ? ? ? ? ? ? ? ?"
#define SIG_FENIXZONE_CHAT					"55 89 E5 56 53 83 EC 10 E8 ? ? ? ?"
#define SIG_FENIXZONE_CHAT_PUSH				"55 89 E5 53 89 C3 83 EC 14 E8 ? ? ? ?"
#define SIG_FENIXZONE_TIMER					"C7 44 24 ? ? ? ? ? C7 44 24 ? ? ? ? ? C7 44 24 ? ? ? ? ? C7 04 24 ? ? ? ? E8 ? ? ? ? 83 EC 10 C7 44 24 ? ? ? ? ? C7 44 24 ? ? ? ? ? C7 44 24 ? ? ? ? ? C7 04 24 ? ? ? ? E8 ? ? ? ?"
#define SIG_FENIXZONE_TIMER_FUNC			"55 89 E5 57 56 53 81 EC ? ? ? ? 83 3D ? ? ? ? ?"

#define SIG_FENIXZONE_ENTRY					"C7 04 24 ? ? ? ? E8 ? ? ? ? 56 8B 80 ? ? ? ? C6 40 04 02 E8"


struct PatternData {
	std::vector<uint8_t> bytes;
	std::vector<bool>    mask;
	uint8_t              firstByte;
	bool                 firstWildcard;
};
static std::unordered_map<std::string, PatternData> s_patternCache;

static PatternData& ParsePattern(const char* sig) {
	auto it = s_patternCache.find(sig);
	if (it != s_patternCache.end()) return it->second;

	PatternData pd;
	const char* cur = sig;
	while (*cur) {
		if (*cur == '?') {
			++cur;
			if (*cur == '?') ++cur;
			pd.bytes.push_back(0);
			pd.mask.push_back(false);
		}
		else {
			pd.bytes.push_back(uint8_t(strtoul(cur, const_cast<char**>(&cur), 16)));
			pd.mask.push_back(true);
		}
		if (*cur == ' ') ++cur;
	}
	pd.firstWildcard = !pd.mask[0];
	pd.firstByte = pd.bytes[0];
	return s_patternCache.emplace(sig, std::move(pd)).first->second;
}

uintptr_t PatternScanRCEOnly(const char* signature, bool skipFirst = false) {
	auto& pat = ParsePattern(signature);
	size_t  pLen = pat.bytes.size();
	if (pLen == 0) return 0;

	MEMORY_BASIC_INFORMATION mbi;
	uintptr_t address = 0;
	bool foundOnce = false;

	while (VirtualQuery((void*)address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
		if (mbi.State == MEM_COMMIT
			&& mbi.Type == MEM_PRIVATE
			&& (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
			&& !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
		{
			auto* region = reinterpret_cast<const uint8_t*>(mbi.BaseAddress);
			size_t  regionSize = mbi.RegionSize;
			if (regionSize >= pLen) {
				const uint8_t* cur = region;
				const uint8_t* end = region + regionSize - pLen;

				while (cur <= end) {
					if (!pat.firstWildcard) {
						cur = (const uint8_t*)memchr(cur, pat.firstByte, (end - cur) + 1);
						if (!cur) break;
					}
					bool ok = true;
					for (size_t j = 0; j < pLen; ++j) {
						if (pat.mask[j] && cur[j] != pat.bytes[j]) {
							ok = false;
							break;
						}
					}
					if (ok) {
						if (skipFirst && !foundOnce) {
							foundOnce = true;
						}
						else {
							return uintptr_t(cur);
						}
					}
					++cur;
				}
			}
		}
		address += mbi.RegionSize;
	}
	return 0;
}


static uintptr_t g_stubEP = 0;
static BYTE* g_mappedBase = nullptr;
static size_t   g_entryRVA = 0;
static constexpr size_t STUB_SCAN_SIZE = 0x300;

BYTE    originalPrologue[9];
BYTE* trampoline = nullptr;
uintptr_t hookAddress = 0;

static int CallOriginal(int a1)
{
	int result;
	__asm {
		mov  eax, a1
		call trampoline
		mov  result, eax
	}
	return result;
}

int __cdecl MySayImpl(int a1, void* returnAddress)
{
	const char* str = reinterpret_cast<const char*>(a1);
	if (!str || IsBadStringPtrA(str, 256))
		return CallOriginal(a1);

	g_pProtectionLog->Log("[FenixZone AC Bypass] Command: %s", str);

	return CallOriginal(a1);
}

__declspec(naked) int MySay()
{
	__asm {
		push[esp]
		push eax
		call MySayImpl
		add esp, 8
		ret
	}
}

typedef void(__stdcall* tTerminateGTA)(HWND, UINT, UINT_PTR, DWORD);
tTerminateGTA oTerminateGTA = nullptr;

void __stdcall hkTerminateGTA(HWND hWnd, UINT msg, UINT_PTR idEvent, DWORD dwTime)
{
// body without calling original - block TerminateProcess if neccesary
}

std::string GenerateButoStringFromMappedMemory()
{
	volatile uint32_t* pSeed = reinterpret_cast<volatile uint32_t*>(g_mappedBase + 0xEBC0);
	volatile uint32_t* pCounter = reinterpret_cast<volatile uint32_t*>(g_mappedBase + 0xF00C);
	uint8_t* byte_6C0CA160 = reinterpret_cast<uint8_t*>(g_mappedBase + 0xA160);

	uint32_t hFileb = *pSeed + 300;
	uint8_t buffer[0x80] = {};
	int v316 = 0;

	while (byte_6C0CA160[v316])
		++v316;

	for (int hObject = 0; hObject < v316; ++hObject)
	{
		uint8_t ch = byte_6C0CA160[hObject];
		uint32_t tmp = ((hFileb >> 3) + 7) ^ (33 * hFileb);

		uint8_t mixed = (uint8_t)((tmp << 5) | (tmp >> 3));
		uint8_t v30 = mixed ^ ch;
		hFileb = mixed;

		uint8_t v31 = (v30 << 3) | (v30 >> 5);
		uint8_t high = (v31 >> 4) & 0xF;
		uint8_t low = v31 & 0xF;

		size_t len = strlen((char*)buffer);
		if (len > 125)
			break;

		buffer[len] = (high <= 9) ? (high + '0') : (high + '7');
		buffer[len + 1] = (low <= 9) ? (low + '0') : (low + '7');
		buffer[len + 2] = 0;
	}

	uint32_t counter = ++(*pCounter);
	if (counter == 2)
	{
		++(*pSeed);
		*pCounter = 0;
	}

	return std::string((char*)buffer);
}

typedef void(__cdecl* tSub6C0C12A8)(
	struct _WIN32_FIND_DATAA* FirstFileA,
	signed int cFileName,
	struct _FILETIME* p_Buffer,
	HWND a4,
	UINT a5,
	UINT_PTR a6,
	DWORD a7);
tSub6C0C12A8 oSub6C0C12A8 = nullptr;

int g_step = 0;

void __cdecl hkSub6C0C12A8(
	struct _WIN32_FIND_DATAA* FirstFileA,
	signed int cFileName,
	struct _FILETIME* p_Buffer,
	HWND a4,
	UINT a5,
	UINT_PTR a6,
	DWORD a7)
{
	if (g_step > 0 && g_step % 15 == 0)
	{
		std::string buto = GenerateButoStringFromMappedMemory();

		char cmd[128];
		snprintf(cmd, sizeof(cmd), "/buto %s", buto.c_str());
		MySayImpl((int)cmd, 0);
	}

	++g_step;

	//oSub6C0C12A8(FirstFileA, cFileName, p_Buffer, a4, a5, a6, a7); // call original - we dont do that here :D
}

bool HookChatPush()
{
	hookAddress = PatternScanRCEOnly(SIG_FENIXZONE_CHAT_PUSH);
	if (!hookAddress) return false;

	constexpr SIZE_T prologueSize = 9;
	memcpy(originalPrologue, (void*)hookAddress, prologueSize);

	trampoline = (BYTE*)VirtualAlloc(NULL, prologueSize + 5,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);
	if (!trampoline) return false;

	memcpy(trampoline, originalPrologue, prologueSize);

	BYTE* p = trampoline + prologueSize;
	p[0] = 0xE9;
	*reinterpret_cast<DWORD*>(p + 1) =
		(DWORD)((hookAddress + prologueSize) - (((uintptr_t)p) + 5));

	DWORD old;
	VirtualProtect((LPVOID)hookAddress, 5,
		PAGE_EXECUTE_READWRITE, &old);
	{
		BYTE* dst = (BYTE*)hookAddress;
		dst[0] = 0xE9; // JMP
		*reinterpret_cast<DWORD*>(dst + 1) =
			(DWORD)((uintptr_t)MySay - (hookAddress + 5));
	}
	VirtualProtect((LPVOID)hookAddress, 5, old, &old);
	return true;
}

bool TryCreateHook(const char* name, uintptr_t sig, LPVOID hookFunc, LPVOID* original)
{
	if (sig == 0)
	{
		g_pProtectionLog->Log("[FenixZone AC Bypass] Signature for %s not found.", name);
		return false;
	}

	if (MH_CreateHook(reinterpret_cast<LPVOID>(sig), hookFunc, original) != MH_OK)
	{
		g_pProtectionLog->Log("[FenixZone AC Bypass] Failed to create hook for %s.", name);
		return false;
	}

	if (MH_EnableHook(reinterpret_cast<LPVOID>(sig)) != MH_OK)
	{
		g_pProtectionLog->Log("[FenixZone AC Bypass] Failed to enable hook for %s.", name);
		return false;
	}

	g_pProtectionLog->Log("[FenixZone AC Bypass] Hooked %s at 0x%p", name, (void*)sig);
	return true;
}

bool FindMethodAndHook()
{
	g_pProtectionLog->Log("[FenixZone AC Bypass] Scanning for signatures...");

	uintptr_t sigTerminateGTA = PatternScan((uint32_t)g_mappedBase, SIG_FENIXZONE_CLOSE, false);
	uintptr_t sigTimerFunc = PatternScan((uint32_t)g_mappedBase, SIG_FENIXZONE_TIMER_FUNC, false);

	bool success = true;

	success &= HookChatPush();
  success &= TryCreateHook("TerminateGTA", sigTerminateGTA, &hkTerminateGTA, reinterpret_cast<LPVOID*>(&oTerminateGTA));
	success &= TryCreateHook("TimerFunc", sigTimerFunc, &hkSub6C0C12A8, reinterpret_cast<LPVOID*>(&oSub6C0C12A8));


	if (success)
		g_pProtectionLog->Log("[FenixZone AC Bypass] All hooks attached successfully.");
	else
		g_pProtectionLog->Log("[FenixZone AC Bypass] One or more hooks failed.");

	return success;
}


void* ManualMapPE_NoEntry(std::vector<unsigned char> exeData)
{
	if (exeData.size() < sizeof(IMAGE_DOS_HEADER))
		return nullptr;

	auto* dosHdr = reinterpret_cast<PIMAGE_DOS_HEADER>(exeData.data());
	if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return nullptr;

	auto* ntHdr = reinterpret_cast<PIMAGE_NT_HEADERS>(exeData.data() + dosHdr->e_lfanew);
	if (ntHdr->Signature != IMAGE_NT_SIGNATURE)
		return nullptr;

	SIZE_T imageSize = ntHdr->OptionalHeader.SizeOfImage;

	BYTE* mapped = (BYTE*)VirtualAlloc(nullptr,
		imageSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);
	if (!mapped) return nullptr;

	SIZE_T headersSize = ntHdr->OptionalHeader.SizeOfHeaders;
	memcpy(mapped, exeData.data(), headersSize);

	auto* section = IMAGE_FIRST_SECTION(ntHdr);
	for (int i = 0; i < ntHdr->FileHeader.NumberOfSections; ++i, ++section)
	{
		if (section->SizeOfRawData == 0) continue;
		BYTE* dest = mapped + section->VirtualAddress;
		const BYTE* src = exeData.data() + section->PointerToRawData;
		memcpy(dest, src, section->SizeOfRawData);
	}

	ULONG_PTR delta = (ULONG_PTR)mapped - ntHdr->OptionalHeader.ImageBase;
	if (delta != 0 && ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
	{
		auto* relocDir = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
			mapped +
			ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

		SIZE_T relocSize = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
		SIZE_T parsed = 0;

		while (parsed < relocSize && relocDir->SizeOfBlock)
		{
			DWORD count = (relocDir->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			auto* entry = reinterpret_cast<WORD*>(relocDir + 1);
			for (DWORD j = 0; j < count; ++j, ++entry)
			{
				WORD type = *entry >> 12;
				WORD offset = *entry & 0x0FFF;
				if (type == IMAGE_REL_BASED_HIGHLOW || type == IMAGE_REL_BASED_DIR64)
				{
					ULONG_PTR* patchAddr = reinterpret_cast<ULONG_PTR*>(
						mapped + relocDir->VirtualAddress + offset);
					*patchAddr = *patchAddr + delta;
				}
			}
			parsed += relocDir->SizeOfBlock;
			relocDir = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<BYTE*>(relocDir) + relocDir->SizeOfBlock);
		}
	}

	auto& impDir = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (impDir.Size)
	{
		auto* importDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
			mapped + impDir.VirtualAddress);
		for (; importDesc->Name; ++importDesc)
		{
			char* dllName = reinterpret_cast<char*>(mapped + importDesc->Name);
			HMODULE hDll = LoadLibraryA(dllName);
			if (!hDll) continue;

			auto* origFirst = reinterpret_cast<PIMAGE_THUNK_DATA>(mapped + importDesc->OriginalFirstThunk);
			auto* first = reinterpret_cast<PIMAGE_THUNK_DATA>(mapped + importDesc->FirstThunk);

			for (; origFirst->u1.AddressOfData; ++origFirst, ++first)
			{
				FARPROC proc = nullptr;
				if (origFirst->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				{
					proc = GetProcAddress(hDll, MAKEINTRESOURCEA(origFirst->u1.Ordinal & 0xFFFF));
				}
				else
				{
					auto* importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
						mapped + origFirst->u1.AddressOfData);
					proc = GetProcAddress(hDll, importByName->Name);
				}
				first->u1.Function = reinterpret_cast<ULONG_PTR>(proc);
			}
		}
	}

	g_mappedBase = mapped;
	auto* dos = (PIMAGE_DOS_HEADER)mapped;
	auto* nt = (PIMAGE_NT_HEADERS)(mapped + dos->e_lfanew);
	g_entryRVA = nt->OptionalHeader.AddressOfEntryPoint;
	return mapped;
}

void PatchMpressStub()
{
	if (!g_mappedBase) return;

	if (!g_stubEP)
	{
		auto* dos = (PIMAGE_DOS_HEADER)g_mappedBase;
		auto* nt = (PIMAGE_NT_HEADERS)(g_mappedBase + dos->e_lfanew);
		g_stubEP = (uintptr_t)g_mappedBase + nt->OptionalHeader.AddressOfEntryPoint;
	}

	DWORD oldProt;
	VirtualProtect((void*)g_stubEP, STUB_SCAN_SIZE,
		PAGE_EXECUTE_READWRITE, &oldProt);

	BYTE* p = (BYTE*)g_stubEP;

	uintptr_t realDllMainAddr = (uintptr_t)g_mappedBase + g_entryRVA;
	for (size_t i = 0; i + 5 <= STUB_SCAN_SIZE; ++i)
	{
		if (p[i] == 0xE8)
		{
			int32_t rel = *reinterpret_cast<int32_t*>(p + i + 1);
			uintptr_t target = (uintptr_t)(p + i + 5) + rel;
			if (target == realDllMainAddr)
			{
				p[i + 0] = 0xC3; // RET
				p[i + 1] = 0x90; // NOP
				p[i + 2] = 0x90;
				p[i + 3] = 0x90;
				p[i + 4] = 0x90;
				break;
			}
		}
	}

	for (size_t i = 0; i + 5 <= STUB_SCAN_SIZE; ++i)
	{
		if (p[i] == 0xE9)
		{
			int32_t rel = *reinterpret_cast<int32_t*>(p + i + 1);
			uintptr_t target = (uintptr_t)(p + i + 5) + rel;
			if (target == realDllMainAddr)
			{
				p[i + 0] = 0xC3;
				p[i + 1] = 0x90;
				p[i + 2] = 0x90;
				p[i + 3] = 0x90;
				p[i + 4] = 0x90;
				break;
			}
		}
	}

	VirtualProtect((void*)g_stubEP, STUB_SCAN_SIZE, oldProt, &oldProt);
}

void CallACRealDllMain()
{
	if (!g_mappedBase || g_entryRVA == 0) return;
	using DllMainT = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);
	auto fn = (DllMainT)(g_mappedBase + g_entryRVA);
	fn((HINSTANCE)g_mappedBase, DLL_PROCESS_ATTACH, nullptr);
}

void Patch_BlockUnwantedThreads(uintptr_t imageBase)
{
	static constexpr std::uintptr_t blockTargets[] = {
		0x5444, // block
		0x724C, // block
		0x53F4, // block
		0x7B24, // block
		0x5458 // block
	};

	uint8_t* base = reinterpret_cast<uint8_t*>(imageBase);

	auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
	auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE) return;

	WORD numSections = nt->FileHeader.NumberOfSections;
	auto sec = IMAGE_FIRST_SECTION(nt);

	int patched = 0;

	for (int i = 0; i < numSections; ++i) {
		DWORD secChar = sec[i].Characteristics;
		if ((secChar & IMAGE_SCN_CNT_CODE) && (secChar & IMAGE_SCN_MEM_EXECUTE)) {
			uintptr_t va = imageBase + sec[i].VirtualAddress;
			uint8_t* code = reinterpret_cast<uint8_t*>(va);
			size_t len = sec[i].Misc.VirtualSize;

			for (size_t j = 0; j + 10 < len; ++j) {
				if (code[j + 0] == 0xC7 &&
					code[j + 1] == 0x44 &&
					code[j + 2] == 0x24 &&
					code[j + 3] == 0x08)
				{
					uint32_t targetAddr = *reinterpret_cast<uint32_t*>(&code[j + 4]);
					uintptr_t relOffset = targetAddr - imageBase;

					for (uintptr_t blocked : blockTargets) {
						if (relOffset == blocked) {
							uint8_t* maybeCall = &code[j + 0x17];
							if (maybeCall[0] == 0xE8) {
								DWORD old;
								VirtualProtect(maybeCall, 5, PAGE_EXECUTE_READWRITE, &old);
								memset(maybeCall, 0x90, 5);
								VirtualProtect(maybeCall, 5, old, &old);

								++patched;
								break;
							}
						}
					}
				}
			}
		}
	}

	g_pProtectionLog->Log("[FenixZone AC Bypass] Patched %d unwanted CreateThread calls.", patched);
}


// Then just use while catching malicious packets (in our case oversized RPC_ShowDialog):
auto testSig = PatternScan((uint32_t)exeData.data()/*malicious packet assembly data*/, "8B FE 66 AD C1 E0 0C 8B C8 50 AD 2B C8 03 F1 8B C8 57", false);
if (testSig != NULL && g_mappedBase == NULL) {
	//g_pProtectionLog->Log("Detected FenixZone Anti Cheat signature in PE executable (rpcId: %i (%s))", rpcId, rpcName.c_str());

	ManualMapPE_NoEntry(exeData);

	g_pProtectionLog->Log("PE executable mapped successfully, base address: 0x%p", g_mappedBase);
	g_pProtectionLog->Log("Patching Mpress stub...");

	PatchMpressStub();

	g_pProtectionLog->Log("Mpress stub patched, calling original DllMain...");

	((void(*)())g_stubEP)();

	g_pProtectionLog->Log("Original DllMain called, bypassing FenixZone Anti Cheat...");

	// Now lets fucking bypass this shit
	{
		if (FindMethodAndHook())
		{
			Patch_BlockUnwantedThreads((uintptr_t)g_mappedBase);
			CallACRealDllMain();

			g_pProtectionLog->Log("FenixZone Anti Cheat bypassed successfully!");
		}
	}
}
