<?php
/** x64 COFF BOF loader via PHP FFI (Windows, PHP 8+, ffi.enabled). */

declare(strict_types=1);

const MEM_COMMIT = 0x1000;
const MEM_RESERVE = 0x2000;
const PAGE_EXECUTE_READWRITE = 0x40;
const MEM_RELEASE = 0x8000;
const IMAGE_FILE_MACHINE_AMD64 = 0x8664;
const IMAGE_SYM_SECTION_UNDEFINED = 0;

const IMAGE_REL_AMD64_ADDR64 = 0x0001;
const IMAGE_REL_AMD64_ADDR32NB = 0x0003;
const IMAGE_REL_AMD64_REL32 = 0x0004;
const IMAGE_REL_AMD64_REL32_1 = 0x0005;
const IMAGE_REL_AMD64_REL32_2 = 0x0006;
const IMAGE_REL_AMD64_REL32_3 = 0x0007;
const IMAGE_REL_AMD64_REL32_4 = 0x0008;
const IMAGE_REL_AMD64_REL32_5 = 0x0009;

final class CoffLoader
{
    private const IMAGE_SYM_ABSOLUTE = -1;

    private FFI $kernel32;
    private FFI $ffiLocal;
    private array $importCache = [];
    private const TRAMP_RESERVE = 65536;
    private const U64_MASK = -1;
    private array $trampCache = [];
    private array $importGotSlots = [];
    private int $trampNext = 0;
    private int $trampLimit = 0;
    private ?int $sharedRetStubVa = null;
    private ?int $beaconPrintfStubVa = null;
    private ?int $beaconOutputStubVa = null;
    private ?int $beaconDataParseVa = null;
    private ?int $beaconDataExtractVa = null;
    private ?int $beaconDataShortVa = null;
    private ?int $beaconDataIntVa = null;
    private ?int $beaconDataLengthVa = null;
    private ?object $altStackShimPtr = null;

    public function __construct()
    {
        $this->ffiLocal = FFI::cdef(
            'typedef union { void* vp; long long si; } __ptr_u64;
            typedef unsigned long long uint64_t;'
        );
        $this->kernel32 = FFI::cdef('
            typedef void* LPVOID;
            typedef void* HMODULE;
            typedef const char* LPCSTR;
            typedef unsigned long DWORD;
            typedef unsigned long long SIZE_T;
            typedef int BOOL;
            typedef short WORD;

            LPVOID VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
            HMODULE GetModuleHandleA(LPCSTR lpModuleName);
            HMODULE LoadLibraryA(LPCSTR lpLibFileName);
            void* GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
            BOOL VirtualFree(void* lpAddress, SIZE_T dwSize, DWORD dwFreeType);
        ', 'kernel32.dll');
    }

    public function runGoInWorkerThread(int $goVa, FFI\CData $argBuffer, int $len): void
    {
        if ($this->altStackShimPtr === null) {
            $entry = "\x53\x48\x8B\xDC\x4C\x8B\xD1\x49\x8B\x02\x49\x8B\x4A\x08"
                . "\x49\x8B\x52\x10\x4D\x8B\x42\x18\x49\x8D\xA0\x00\xF0\xFF\xFF\x48\x83\xE4\xF0"
                . "\xFF\xD0\x48\x8B\xE3\x5B\x33\xC0\xC3";
            $p = $this->kernel32->VirtualAlloc(
                null,
                (int) strlen($entry),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE
            );
            if ($p === null) {
                throw new RuntimeException('VirtualAlloc failed for alt-stack shim');
            }
            FFI::memcpy(FFI::cast('char*', $p), $entry, strlen($entry));
            $this->altStackShimPtr = $p;
        }

        $stackSize = 8 * 1024 * 1024;
        $stack = $this->kernel32->VirtualAlloc(
            null,
            $stackSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        if ($stack === null) {
            throw new RuntimeException('VirtualAlloc failed for BOF stack');
        }
        $pack = $this->kernel32->VirtualAlloc(
            null,
            32,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        if ($pack === null) {
            $this->kernel32->VirtualFree($stack, 0, MEM_RELEASE);
            throw new RuntimeException('VirtualAlloc failed for go params');
        }
        try {
            $base = $this->ptrToInt($stack);
            $stackTop = ($base + $stackSize) & ~15;
            $packInt = $this->ptrToInt($pack);
            $this->writeU64($packInt, $goVa & self::U64_MASK);
            $argPtr = $this->ptrToInt(FFI::cast('void*', FFI::addr($argBuffer)));
            $this->writeU64($packInt + 8, $argPtr & self::U64_MASK);
            $this->writeU64($packInt + 16, $len & self::U64_MASK);
            $this->writeU64($packInt + 24, $stackTop & self::U64_MASK);

            $invoke = FFI::cast('void (*)(void*)', $this->altStackShimPtr);
            $invoke(FFI::cast('void*', $pack));
        } finally {
            $this->kernel32->VirtualFree($pack, 0, MEM_RELEASE);
            $this->kernel32->VirtualFree($stack, 0, MEM_RELEASE);
        }
    }

    private function ptrToInt(object $ptr): int
    {
        $u = $this->ffiLocal->new('__ptr_u64');
        $u->vp = FFI::cast('void*', $ptr);
        return (int) $u->si;
    }

    public function proc(string $module, string $name): int
    {
        $mod = $this->kernel32->GetModuleHandleA($module);
        if ($mod === null) {
            $mod = $this->kernel32->LoadLibraryA($module);
        }
        if ($mod === null) {
            throw new RuntimeException("Could not load module {$module}");
        }
        $p = $this->kernel32->GetProcAddress($mod, $name);
        if ($p === null) {
            throw new RuntimeException("GetProcAddress failed for {$module}!{$name}");
        }
        return $this->ptrToInt($p);
    }

    public function load(string $path, array $externs = []): array
    {
        $data = file_get_contents($path);
        if ($data === false || strlen($data) < 20) {
            throw new RuntimeException('Cannot read COFF or file too small');
        }

        $machine = unpack('v', $data, 0)[1];
        if ($machine !== IMAGE_FILE_MACHINE_AMD64) {
            throw new RuntimeException(sprintf('Need AMD64 COFF (0x8664), got 0x%04x', $machine));
        }

        $numSections = unpack('v', $data, 2)[1];
        $ptrSymTab = unpack('V', $data, 8)[1];
        $numSymbols = unpack('V', $data, 12)[1];

        $off = 20;
        $sections = [];
        for ($i = 0; $i < $numSections; $i++) {
            $sections[] = $this->parseSectionHeader($data, $off);
            $off += 40;
        }

        $sections = $this->layoutSections($sections);

        [$symbolsByIndex,] = $this->parseSymbolTable($data, $ptrSymTab, $numSymbols);

        $externMap = [];
        foreach ($externs as $k => $addr) {
            $externMap[strtolower($k)] = $addr;
        }

        $this->importCache = [];
        $this->trampCache = [];
        $this->importGotSlots = [];
        $this->beaconPrintfStubVa = null;
        $this->beaconOutputStubVa = null;
        $this->beaconDataParseVa = null;
        $this->beaconDataExtractVa = null;
        $this->beaconDataShortVa = null;
        $this->beaconDataIntVa = null;
        $this->beaconDataLengthVa = null;

        $imageSize = $this->computeImageSize($sections);
        $base = $this->kernel32->VirtualAlloc(
            null,
            $imageSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        if ($base === null) {
            throw new RuntimeException('VirtualAlloc failed');
        }

        $baseInt = $this->ptrToInt($base);
        $spanEnd = $this->sectionSpanEnd($sections);
        $this->trampNext = $baseInt + (($spanEnd + 15) & ~15);
        $this->trampLimit = $baseInt + $imageSize;

        foreach ($sections as $sec) {
            if ($sec['SizeOfRawData'] === 0) {
                continue;
            }
            $src = substr($data, $sec['PointerToRawData'], $sec['SizeOfRawData']);
            $need = max($sec['VirtualSize'], strlen($src));
            $blob = $src . str_repeat("\0", max(0, $need - strlen($src)));
            $dst = FFI::cast('char*', $base) + $sec['LoadRVA'];
            FFI::memcpy($dst, $blob, strlen($blob));
        }

        $symAddr = $this->definedSymbolAddresses($sections, $symbolsByIndex, $base);

        foreach ($sections as $sec) {
            $this->applyRelocations(
                $data,
                $sec,
                $sections,
                $base,
                $symbolsByIndex,
                $numSymbols,
                $symAddr,
                $externMap
            );
        }

        $goVa = $symAddr['go'] ?? $symAddr['_go'] ?? null;
        $go = $goVa !== null
            ? FFI::cast('void (*)(void*, uint64_t)', FFI::cast('void*', $goVa))
            : null;

        return [
            'base' => $base,
            'size' => $imageSize,
            'go' => $go,
            'goVa' => $goVa,
        ];
    }

    private function layoutSections(array $sections): array
    {
        $allZero = true;
        foreach ($sections as $s) {
            if (($s['VirtualAddress'] ?? 0) !== 0 || ($s['VirtualSize'] ?? 0) !== 0) {
                $allZero = false;
                break;
            }
        }
        $out = [];
        if (!$allZero) {
            foreach ($sections as $s) {
                $s['LoadRVA'] = $s['VirtualAddress'];
                $out[] = $s;
            }
            return $out;
        }
        $next = 0;
        foreach ($sections as $s) {
            $align = $this->sectionAlignment($s['Characteristics']);
            $next = ($next + $align - 1) & ~($align - 1);
            $s['LoadRVA'] = $next;
            $span = max($s['VirtualSize'], $s['SizeOfRawData']);
            $out[] = $s;
            $next += $span;
        }
        return $out;
    }

    private function sectionAlignment(int $characteristics): int
    {
        $idx = ($characteristics >> 20) & 0xF;
        if ($idx <= 1) {
            return 16;
        }
        return 1 << ($idx - 1);
    }

    private function sectionSpanEnd(array $sections): int
    {
        $max = 0;
        foreach ($sections as $sec) {
            $rva = $sec['LoadRVA'] ?? $sec['VirtualAddress'];
            $end = $rva + max($sec['VirtualSize'], $sec['SizeOfRawData']);
            $max = max($max, $end);
        }
        return $max;
    }

    private function computeImageSize(array $sections): int
    {
        $span = $this->sectionSpanEnd($sections);
        return ($span + self::TRAMP_RESERVE + 0xFFF) & ~0xFFF;
    }

    private function parseSectionHeader(string $data, int $off): array
    {
        return [
            'Name' => rtrim(substr($data, $off, 8), "\0"),
            'VirtualSize' => unpack('V', $data, $off + 8)[1],
            'VirtualAddress' => unpack('V', $data, $off + 12)[1],
            'SizeOfRawData' => unpack('V', $data, $off + 16)[1],
            'PointerToRawData' => unpack('V', $data, $off + 20)[1],
            'PointerToRelocations' => unpack('V', $data, $off + 24)[1],
            'NumberOfRelocations' => unpack('v', $data, $off + 32)[1],
            'Characteristics' => unpack('V', $data, $off + 36)[1],
        ];
    }

    private function parseSymbolTable(string $data, int $ptrSymTab, int $numSymbols): array
    {
        $byIndex = array_fill(0, $numSymbols, null);
        $i = 0;
        while ($i < $numSymbols) {
            $off = $ptrSymTab + $i * 18;
            $w0 = unpack('V', $data, $off)[1];
            $w1 = unpack('V', $data, $off + 4)[1];
            $value = unpack('V', $data, $off + 8)[1];
            $rawSec = unpack('v', $data, $off + 12)[1];
            $sectionNumber = ($rawSec > 0x7FFF) ? $rawSec - 65536 : $rawSec;
            $storageClass = ord($data[$off + 16]);
            $numAux = ord($data[$off + 17]);

            if ($w0 === 0 && $w1 !== 0) {
                $strDataStart = $ptrSymTab + $numSymbols * 18 + 4;
                $name = $this->readCString(substr($data, $strDataStart + $w1));
            } else {
                $name = rtrim(substr($data, $off, 8), "\0");
            }

            $byIndex[$i] = [
                'name' => $name,
                'value' => $value,
                'sectionNumber' => $sectionNumber,
                'storageClass' => $storageClass,
                'numAux' => $numAux,
            ];
            for ($a = 1; $a <= $numAux; $a++) {
                $byIndex[$i + $a] = ['aux' => true];
            }
            $i += 1 + $numAux;
        }

        $strTable = substr($data, $ptrSymTab + $numSymbols * 18);
        return [$byIndex, $strTable];
    }

    private function readCString(string $blob): string
    {
        $z = strpos($blob, "\0");
        return $z === false ? $blob : substr($blob, 0, $z);
    }

    private function definedSymbolAddresses(array $sections, array $symbolsByIndex, $base): array
    {
        $map = [];
        $nsec = count($sections);
        foreach ($symbolsByIndex as $sym) {
            if (!is_array($sym) || isset($sym['aux'])) {
                continue;
            }
            $sn = $sym['sectionNumber'];
            if ($sn <= 0 || $sn > $nsec) {
                continue;
            }
            $sec = $sections[$sn - 1];
            $rva = $sec['LoadRVA'] ?? $sec['VirtualAddress'];
            $va = $this->ptrToInt($base) + $rva + $sym['value'];
            $map[strtolower($sym['name'])] = $va;
        }
        return $map;
    }

    private function applyRelocations(
        string $data,
        array $sec,
        array $sections,
        $base,
        array $symbolsByIndex,
        int $numFileSymbols,
        array $symAddr,
        array $externMap
    ): void {
        $n = $sec['NumberOfRelocations'];
        if ($n === 0) {
            return;
        }
        $relOff = $sec['PointerToRelocations'];
        $secRva = $sec['LoadRVA'] ?? $sec['VirtualAddress'];
        $secBase = $this->ptrToInt($base) + $secRva;

        for ($r = 0; $r < $n; $r++) {
            $o = $relOff + $r * 10;
            $vaddr = unpack('V', $data, $o)[1];
            $symIndex = unpack('V', $data, $o + 4)[1];
            $type = unpack('v', $data, $o + 8)[1];

            if ($symIndex >= $numFileSymbols) {
                throw new RuntimeException(
                    "Invalid relocation symbol index {$symIndex} (file has {$numFileSymbols} symbol records)"
                );
            }
            $sym = $symbolsByIndex[$symIndex];
            if (!is_array($sym) || isset($sym['aux'])) {
                throw new RuntimeException(
                    "Relocation uses symbol index {$symIndex} (aux or empty); not supported"
                );
            }
            $loc = $secBase + $vaddr;
            if ($type === IMAGE_REL_AMD64_ADDR64) {
                if ($sym['sectionNumber'] === IMAGE_SYM_SECTION_UNDEFINED) {
                    $slot = $this->importGotSlotVa($sym, $sections, $base, $symAddr, $externMap);
                    $this->writeU64($loc, $slot & self::U64_MASK);
                } else {
                    $cur = $this->readU64($loc);
                    $symVa = $this->symbolValue($sym, $sections, $base, $symAddr, $externMap);
                    $this->writeU64($loc, ($cur + $symVa) & self::U64_MASK);
                }
            } elseif ($type === IMAGE_REL_AMD64_ADDR32NB) {
                $cur = unpack('V', $this->readMem($loc, 4), 0)[1];
                if ($sym['sectionNumber'] === IMAGE_SYM_SECTION_UNDEFINED) {
                    $slot = $this->importGotSlotVa($sym, $sections, $base, $symAddr, $externMap);
                    $delta = (int) ($slot - ($loc + 4));
                } else {
                    $imageBase = $this->ptrToInt($base);
                    $symVa = $this->symbolValue($sym, $sections, $base, $symAddr, $externMap);
                    $delta = (int) ($cur + $symVa - $imageBase);
                }
                $this->writeU32($loc, $delta & 0xFFFFFFFF);
            } elseif ($type === IMAGE_REL_AMD64_REL32) {
                $symVa = $this->relocatedSymbolVa($sym, $loc, $type, $sections, $base, $symAddr, $externMap);
                $this->patchRel32($loc, $symVa, 0);
            } elseif ($type >= IMAGE_REL_AMD64_REL32_1 && $type <= IMAGE_REL_AMD64_REL32_5) {
                $symVa = $this->relocatedSymbolVa($sym, $loc, $type, $sections, $base, $symAddr, $externMap);
                $this->patchRel32($loc, $symVa, $type - IMAGE_REL_AMD64_REL32);
            } else {
                throw new RuntimeException(sprintf(
                    'Unsupported relocation type 0x%04x at section %s offset 0x%x',
                    $type,
                    $sec['Name'],
                    $vaddr
                ));
            }
        }
    }

    private function relocatedSymbolVa(
        array $sym,
        int $loc,
        int $relocType,
        array $sections,
        $base,
        array $symAddr,
        array $externMap
    ): int {
        $ripRelFamily = $relocType === IMAGE_REL_AMD64_REL32
            || ($relocType >= IMAGE_REL_AMD64_REL32_1 && $relocType <= IMAGE_REL_AMD64_REL32_5);
        if ($ripRelFamily && $sym['sectionNumber'] === IMAGE_SYM_SECTION_UNDEFINED) {
            if ($this->ripRelativeIndirectUsesGot($loc)) {
                return $this->importGotSlotVa($sym, $sections, $base, $symAddr, $externMap);
            }
        }
        return $this->symbolValue($sym, $sections, $base, $symAddr, $externMap);
    }

    private function ripRelativeIndirectUsesGot(int $loc): bool
    {
        $max = min(8, $loc);
        for ($n = 2; $n <= $max; $n++) {
            $chunk = $this->readMem($loc - $n, $n);
            if (str_ends_with($chunk, "\xFF\x15") || str_ends_with($chunk, "\xFF\x25")) {
                return true;
            }
            if ($n >= 3) {
                $op = ord($chunk[$n - 2]);
                $modrm = ord($chunk[$n - 1]);
                if ($op === 0x8B && ($modrm & 0xC7) === 0x05) {
                    return true;
                }
            }
        }

        return false;
    }

    private function importGotSlotVa(
        array $sym,
        array $sections,
        $base,
        array $symAddr,
        array $externMap
    ): int {
        $key = strtolower($sym['name']);
        if (isset($this->importGotSlots[$key])) {
            return $this->importGotSlots[$key];
        }
        $fnVa = $this->symbolValue($sym, $sections, $base, $symAddr, $externMap);
        $slot = $this->allocateGotSlot($fnVa);
        $this->importGotSlots[$key] = $slot;
        return $slot;
    }

    private function allocateGotSlot(int $funcPtr): int
    {
        $addr = ($this->trampNext + 7) & ~7;
        if ($addr + 8 > $this->trampLimit) {
            throw new RuntimeException('GOT arena exhausted; increase TRAMP_RESERVE');
        }
        $this->writeU64($addr, $funcPtr);
        $this->trampNext = $addr + 8;
        return $addr;
    }

    private function symbolValue(array $sym, array $sections, $base, array $symAddr, array $externMap): int
    {
        $sn = $sym['sectionNumber'];
        if ($sn === IMAGE_SYM_SECTION_UNDEFINED) {
            if (stripos($sym['name'], '__C_specific_handler') !== false) {
                return 0;
            }
            $key = strtolower($sym['name']);
            if (isset($externMap[$key])) {
                return $externMap[$key];
            }
            $auto = $this->autoResolveImport($sym['name']);
            if ($auto !== null) {
                return $auto;
            }
            throw new RuntimeException("Unresolved external: {$sym['name']}");
        }
        if ($sn > 0 && $sn <= count($sections)) {
            $s = $sections[$sn - 1];
            $rva = $s['LoadRVA'] ?? $s['VirtualAddress'];
            return $this->ptrToInt($base) + $rva + $sym['value'];
        }
        if ($sn === self::IMAGE_SYM_ABSOLUTE) {
            return $sym['value'];
        }
        return $sym['value'];
    }

    private function tryProcDllExport(string $dll, string $procName): ?int
    {
        if (strcasecmp($dll, 'kernel32.dll') === 0
            && strcasecmp($procName, 'GetEnvironmentStrings') === 0) {
            return $this->tryProc($dll, 'GetEnvironmentStringsA');
        }
        return $this->tryProc($dll, $procName);
    }

    private function autoResolveImport(string $symName): ?int
    {
        $key = strtolower($symName);
        if (isset($this->importCache[$key])) {
            return $this->importCache[$key];
        }
        if (preg_match('/^p_([^$]+)\$(.+)$/i', $symName, $m)) {
            $dll = strtolower($m[1]);
            if (!str_ends_with($dll, '.dll')) {
                $dll .= '.dll';
            }
            $addr = $this->tryProcDllExport($dll, $m[2]);
            if ($addr !== null) {
                $this->importCache[$key] = $addr;
                return $addr;
            }
        }
        if (str_starts_with($key, '__imp_')) {
            $rest = substr($symName, strlen('__imp_'));
            $restl = strtolower($rest);
            if ($restl === 'beaconoutput') {
                $addr = $this->beaconOutputNativePtr();
                $this->importCache[$key] = $addr;
                return $addr;
            }
            if ($restl === 'beaconprintf') {
                $addr = $this->beaconPrintfNativePtr();
                $this->importCache[$key] = $addr;
                return $addr;
            }
            $beaconData = [
                'beacondataparse' => 'beaconDataParseNativePtr',
                'beacondataextract' => 'beaconDataExtractNativePtr',
                'beacondatashort' => 'beaconDataShortNativePtr',
                'beacondataint' => 'beaconDataIntNativePtr',
                'beacondatalength' => 'beaconDataLengthNativePtr',
            ];
            if (isset($beaconData[$restl])) {
                $mth = $beaconData[$restl];
                $addr = $this->{$mth}();
                $this->importCache[$key] = $addr;
                return $addr;
            }
            if (preg_match('/^([^$]+)\$(.+)$/i', $rest, $m)) {
                $dll = strtolower($m[1]);
                if (!str_ends_with($dll, '.dll')) {
                    $dll .= '.dll';
                }
                $addr = $this->tryProcDllExport($dll, $m[2]);
                if ($addr !== null) {
                    $this->importCache[$key] = $addr;
                    return $addr;
                }
            }
            foreach (['kernel32.dll', 'ntdll.dll', 'advapi32.dll', 'user32.dll', 'msvcrt.dll'] as $dll) {
                $addr = $this->tryProc($dll, $rest);
                if ($addr !== null) {
                    $this->importCache[$key] = $addr;
                    return $addr;
                }
            }
        }
        if (preg_match('/^p_([^$]+)$/i', $symName, $m)) {
            $api = strtolower($m[1]);
            if ($api === 'beaconoutput') {
                $addr = $this->beaconOutputNativePtr();
                $this->importCache[$key] = $addr;
                return $addr;
            }
            if ($api === 'beaconprintf') {
                $addr = $this->beaconPrintfNativePtr();
                $this->importCache[$key] = $addr;
                return $addr;
            }
            if ($api === 'beacondataparse') {
                $addr = $this->beaconDataParseNativePtr();
                $this->importCache[$key] = $addr;
                return $addr;
            }
            if ($api === 'beacondataextract') {
                $addr = $this->beaconDataExtractNativePtr();
                $this->importCache[$key] = $addr;
                return $addr;
            }
            if ($api === 'beacondatashort') {
                $addr = $this->beaconDataShortNativePtr();
                $this->importCache[$key] = $addr;
                return $addr;
            }
            if ($api === 'beacondataint') {
                $addr = $this->beaconDataIntNativePtr();
                $this->importCache[$key] = $addr;
                return $addr;
            }
            if ($api === 'beacondatalength') {
                $addr = $this->beaconDataLengthNativePtr();
                $this->importCache[$key] = $addr;
                return $addr;
            }
            $addr = $this->sharedRetStub();
            $this->importCache[$key] = $addr;
            return $addr;
        }
        return null;
    }

    private function beaconOutputNativePtr(): int
    {
        if ($this->beaconOutputStubVa !== null) {
            return $this->beaconOutputStubVa;
        }
        $getStd = $this->tryProc('kernel32.dll', 'GetStdHandle');
        $writeFile = $this->tryProc('kernel32.dll', 'WriteFile');
        $stub = "\x48\x83\xEC\x08"
            . "\x48\x83\xEC\x70"
            . "\x48\x89\x54\x24\x50"
            . "\x44\x89\x44\x24\x58"
            . "\xB9\xF5\xFF\xFF\xFF"
            . "\x48\xB8" . $this->packAddr64($getStd)
            . "\x48\x83\xEC\x20"
            . "\xFF\xD0"
            . "\x48\x83\xC4\x20"
            . "\x48\x89\x44\x24\x30"
            . "\x48\x8B\x4C\x24\x30"
            . "\x48\x8B\x54\x24\x50"
            . "\x44\x8B\x44\x24\x58"
            . "\x4C\x8D\x4C\x24\x60"
            . "\x48\x83\xEC\x20"
            . "\x48\xC7\x44\x24\x20\x00\x00\x00\x00"
            . "\x48\xB8" . $this->packAddr64($writeFile)
            . "\xFF\xD0"
            . "\x48\x83\xC4\x20"
            . "\x48\x83\xC4\x70"
            . "\x48\x83\xC4\x08"
            . "\xC3";
        $p = $this->kernel32->VirtualAlloc(
            null,
            strlen($stub),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        if ($p === null) {
            throw new RuntimeException('VirtualAlloc failed for BeaconOutput stub');
        }
        FFI::memcpy(FFI::cast('char*', $p), $stub, strlen($stub));
        $this->beaconOutputStubVa = $this->ptrToInt($p);

        return $this->beaconOutputStubVa;
    }

    private function beaconPrintfNativePtr(): int
    {
        if ($this->beaconPrintfStubVa !== null) {
            return $this->beaconPrintfStubVa;
        }
        $out = $this->beaconOutputNativePtr();

        $vsn = $this->tryProc('msvcrt.dll', '_vsnprintf')
            ?? $this->tryProc('msvcrt.dll', 'vsnprintf')
            ?? $this->tryProc('ucrtbase.dll', '_vsnprintf');
        if ($vsn === null) {
            throw new RuntimeException('Need msvcrt._vsnprintf for BeaconPrintf');
        }
        $stub = "\x45\x33\xDB"
            . "\x48\x89\xE0"
            . "\x48\xA9\x08\x00\x00\x00"
            . "\x75\x07"
            . "\x48\x83\xEC\x08"
            . "\x41\xB3\x01"
            . "\x48\x83\xEC\x38"
            . "\x48\x89\x4C\x24\x08"
            . "\x48\x89\x54\x24\x10"
            . "\x4C\x89\x44\x24\x18"
            . "\x4C\x89\x4C\x24\x20"
            . "\x44\x88\x5C\x24\x28"
            . "\x48\x81\xEC\x30\x10\x00\x00"
            . "\x48\x8D\x4C\x24\x30"
            . "\xBA\xFF\x0F\x00\x00"
            . "\x4C\x8B\x84\x24\x40\x10\x00\x00"
            . "\x4C\x8D\x8C\x24\x48\x10\x00\x00"
            . "\x48\x83\xEC\x20"
            . "\x48\xB8" . $this->packAddr64($vsn)
            . "\xFF\xD0"
            . "\x48\x83\xC4\x20"
            . "\x48\x8B\x8C\x24\x38\x10\x00\x00"
            . "\x48\x8D\x54\x24\x30"
            . "\x4C\x63\xC0"
            . "\x85\xC0"
            . "\x79\x03"
            . "\x45\x33\xC0"
            . "\x48\x83\xEC\x20"
            . "\x48\xB8" . $this->packAddr64($out)
            . "\xFF\xD0"
            . "\x48\x83\xC4\x20"
            . "\x0F\xB6\x84\x24\x58\x10\x00\x00"
            . "\x48\x81\xC4\x68\x10\x00\x00"
            . "\x85\xC0"
            . "\x74\x05"
            . "\x48\x83\xC4\x08"
            . "\xC3";

        $p = $this->kernel32->VirtualAlloc(
            null,
            (int) strlen($stub),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        if ($p === null) {
            throw new RuntimeException('VirtualAlloc failed for BeaconPrintf stub');
        }
        FFI::memcpy(FFI::cast('char*', $p), $stub, strlen($stub));
        $this->beaconPrintfStubVa = $this->ptrToInt($p);

        return $this->beaconPrintfStubVa;
    }

    private function beaconDataParseNativePtr(): int
    {
        if ($this->beaconDataParseVa !== null) {
            return $this->beaconDataParseVa;
        }
        $stub = "\x48\x85\xC9\x74\x16\x48\x89\x11\x48\x8D\x42\x04\x48\x89\x41\x08"
            . "\x44\x89\xC0\x83\xE8\x04\x89\x41\x10\x89\x41\x14\xC3";
        $p = $this->kernel32->VirtualAlloc(
            null,
            (int) strlen($stub),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        if ($p === null) {
            throw new RuntimeException('VirtualAlloc failed for BeaconDataParse stub');
        }
        FFI::memcpy(FFI::cast('char*', $p), $stub, strlen($stub));
        $this->beaconDataParseVa = $this->ptrToInt($p);

        return $this->beaconDataParseVa;
    }

    private function beaconDataExtractNativePtr(): int
    {
        if ($this->beaconDataExtractVa !== null) {
            return $this->beaconDataExtractVa;
        }
        $stub = "\x48\x85\xC9\x74\x35\x4C\x8B\x51\x08\x44\x8B\x49\x10\x41\x83\xF9\x04\x72\x27"
            . "\x41\x8B\x02\x4D\x8D\x5A\x04\x41\x83\xE9\x04\x44\x2B\xC8\x4D\x8B\xD3\x4C\x03\xD0"
            . "\x4C\x89\x51\x08\x44\x89\x49\x10\x48\x85\xD2\x74\x02\x89\x02\x49\x8B\xC3\xC3\x33\xC0\xC3";
        $p = $this->kernel32->VirtualAlloc(
            null,
            (int) strlen($stub),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        if ($p === null) {
            throw new RuntimeException('VirtualAlloc failed for BeaconDataExtract stub');
        }
        FFI::memcpy(FFI::cast('char*', $p), $stub, strlen($stub));
        $this->beaconDataExtractVa = $this->ptrToInt($p);

        return $this->beaconDataExtractVa;
    }

    private function beaconDataShortNativePtr(): int
    {
        if ($this->beaconDataShortVa !== null) {
            return $this->beaconDataShortVa;
        }
        $stub = "\x48\x85\xC9\x74\x27\x4C\x8B\x41\x08\x44\x8B\x49\x10\x41\x83\xF9\x02\x72\x19"
            . "\x41\x0F\xB7\x00\x49\x83\xC0\x02\x4C\x89\x41\x08\x41\x83\xE9\x02\x44\x89\x49\x10"
            . "\x48\x0F\xBF\xC0\xC3\x33\xC0\xC3";
        $p = $this->kernel32->VirtualAlloc(
            null,
            (int) strlen($stub),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        if ($p === null) {
            throw new RuntimeException('VirtualAlloc failed for BeaconDataShort stub');
        }
        FFI::memcpy(FFI::cast('char*', $p), $stub, strlen($stub));
        $this->beaconDataShortVa = $this->ptrToInt($p);

        return $this->beaconDataShortVa;
    }

    private function beaconDataIntNativePtr(): int
    {
        if ($this->beaconDataIntVa !== null) {
            return $this->beaconDataIntVa;
        }
        $stub = "\x48\x85\xC9\x74\x22\x4C\x8B\x41\x08\x44\x8B\x49\x10\x41\x83\xF9\x04\x72\x14"
            . "\x41\x8B\x00\x49\x83\xC0\x04\x4C\x89\x41\x08\x41\x83\xE9\x04\x44\x89\x49\x10"
            . "\xC3\x33\xC0\xC3";
        $p = $this->kernel32->VirtualAlloc(
            null,
            (int) strlen($stub),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        if ($p === null) {
            throw new RuntimeException('VirtualAlloc failed for BeaconDataInt stub');
        }
        FFI::memcpy(FFI::cast('char*', $p), $stub, strlen($stub));
        $this->beaconDataIntVa = $this->ptrToInt($p);

        return $this->beaconDataIntVa;
    }

    private function beaconDataLengthNativePtr(): int
    {
        if ($this->beaconDataLengthVa !== null) {
            return $this->beaconDataLengthVa;
        }
        $stub = "\x48\x85\xC9\x74\x07\x8B\x41\x10\xC3\x33\xC0\xC3";
        $p = $this->kernel32->VirtualAlloc(
            null,
            (int) strlen($stub),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        if ($p === null) {
            throw new RuntimeException('VirtualAlloc failed for BeaconDataLength stub');
        }
        FFI::memcpy(FFI::cast('char*', $p), $stub, strlen($stub));
        $this->beaconDataLengthVa = $this->ptrToInt($p);

        return $this->beaconDataLengthVa;
    }

    private function sharedRetStub(): int
    {
        if ($this->sharedRetStubVa !== null) {
            return $this->sharedRetStubVa;
        }
        $p = $this->kernel32->VirtualAlloc(
            null,
            16,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        if ($p === null) {
            throw new RuntimeException('VirtualAlloc failed for ret stub');
        }
        FFI::memcpy(FFI::cast('char*', $p), "\xC3", 1);
        $this->sharedRetStubVa = $this->ptrToInt($p);
        return $this->sharedRetStubVa;
    }

    private function tryProc(string $dll, string $procName): ?int
    {
        $mod = $this->kernel32->GetModuleHandleA($dll);
        if ($mod === null) {
            $mod = $this->kernel32->LoadLibraryA($dll);
        }
        if ($mod === null) {
            return null;
        }
        $p = $this->kernel32->GetProcAddress($mod, $procName);
        if ($p === null) {
            return null;
        }
        return $this->ptrToInt($p);
    }

    private function trampolineFor(int $targetVa): int
    {
        if (isset($this->trampCache[$targetVa])) {
            return $this->trampCache[$targetVa];
        }
        $stubLen = 12;
        if ($this->trampNext + $stubLen > $this->trampLimit) {
            throw new RuntimeException('Trampoline arena exhausted; increase TRAMP_RESERVE');
        }
        $addr = $this->trampNext;
        FFI::memcpy(FFI::cast('char*', $addr), "\x48\xB8", 2);
        $this->writeU64($addr + 2, $targetVa);
        FFI::memcpy(FFI::cast('char*', $addr + 10), "\xFF\xE0", 2);
        $this->trampNext = ($addr + $stubLen + 15) & ~15;
        $this->trampCache[$targetVa] = $addr;
        return $addr;
    }

    private function patchRel32(int $loc, int $symVa, int $extraBytes): void
    {
        $cur = unpack('l', $this->readMem($loc, 4), 0)[1];
        $ref = $loc + 4 + $extraBytes;
        $target = $symVa;
        $disp = $target - $ref + $cur;
        if ($disp > 0x7FFFFFFF || $disp < -0x80000000) {
            $target = $this->trampolineFor($symVa);
            $disp = $target - $ref + $cur;
            if ($disp > 0x7FFFFFFF || $disp < -0x80000000) {
                throw new RuntimeException('REL32 displacement overflow after trampoline');
            }
        }
        $this->writeU32($loc, unpack('V', pack('l', (int) $disp), 0)[1]);
    }

    private function readMem(int $addr, int $len): string
    {
        $p = FFI::new('char[' . $len . ']');
        FFI::memcpy($p, FFI::cast('char*', $addr), $len);
        return FFI::string($p, $len);
    }

    private function packAddr64(int $v): string
    {
        return pack('V', $v & 0xFFFFFFFF) . pack('V', ($v >> 32) & 0xFFFFFFFF);
    }

    private function readU64(int $addr): int
    {
        $b = $this->readMem($addr, 8);
        $lo = unpack('V', $b, 0)[1];
        $hi = unpack('V', $b, 4)[1];
        return $lo + ($hi << 32);
    }

    private function writeU32(int $addr, int $v): void
    {
        $blob = pack('V', $v & 0xFFFFFFFF);
        FFI::memcpy(FFI::cast('char*', $addr), $blob, 4);
    }

    private function writeU64(int $addr, int $v): void
    {
        $lo = $v & 0xFFFFFFFF;
        $hi = ($v >> 32) & 0xFFFFFFFF;
        $blob = pack('V', $lo) . pack('V', $hi);
        FFI::memcpy(FFI::cast('char*', $addr), $blob, 8);
    }
}

function bofCliNormalizeStringArg(string $val): string
{
    $val = trim($val);
    $len = strlen($val);
    if ($len >= 2) {
        $a = $val[0];
        $b = $val[$len - 1];
        if (($a === '"' && $b === '"') || ($a === "'" && $b === "'")) {
            $val = substr($val, 1, -1);
        }
    }
    if (preg_match('/^[A-Za-z]:[\\/]/', $val)) {
        $val = strtr($val, '/', '\\');
    }

    return $val;
}

function bofCliBuildArgpack(array $tokens): string
{
    $onlyEmpty = true;
    foreach ($tokens as $t) {
        if ($t !== '') {
            $onlyEmpty = false;
            break;
        }
    }
    if ($onlyEmpty) {
        return "\0\0\0\0";
    }

    if (count($tokens) === 1 && preg_match('/\A[0-9a-fA-F]+\z/', $tokens[0]) && strlen($tokens[0]) % 2 === 0) {
        $bin = hex2bin($tokens[0]);
        if ($bin === false) {
            return '';
        }
        return $bin;
    }

    $body = '';
    $size = 0;
    foreach ($tokens as $raw) {
        if ($raw === '') {
            continue;
        }
        if (preg_match('/^(str|wstr|int|short|bin):(.*)$/Ds', $raw, $m)) {
            $kind = strtolower($m[1]);
            $val = $m[2];
            if ($kind === 'str' || $kind === 'wstr') {
                $val = bofCliNormalizeStringArg($val);
            }
            if ($kind === 'str') {
                $sb = $val . "\0";
                $n = strlen($sb);
                $body .= pack('V', $n) . $sb;
                $size += 4 + $n;
            } elseif ($kind === 'wstr') {
                $wide = iconv('UTF-8', 'UTF-16LE//IGNORE', $val);
                if ($wide === false) {
                    return '';
                }
                $wide .= "\0\0";
                $byteLen = strlen($wide);
                $body .= pack('V', $byteLen) . $wide;
                $size += 4 + $byteLen;
            } elseif ($kind === 'int') {
                if (!preg_match('/^[-+]?\d+$/', $val)) {
                    return '';
                }
                $body .= pack('l', (int) $val);
                $size += 4;
            } elseif ($kind === 'short') {
                if (!preg_match('/^[-+]?\d+$/', $val)) {
                    return '';
                }
                $body .= pack('v', (int) $val & 0xFFFF);
                $size += 2;
            } elseif ($kind === 'bin') {
                $bin = base64_decode($val, true);
                if ($bin === false) {
                    return '';
                }
                $n = strlen($bin);
                $body .= pack('V', $n) . $bin;
                $size += 4 + $n;
            } else {
                return '';
            }
        } else {
            $sb = $raw . "\0";
            $n = strlen($sb);
            $body .= pack('V', $n) . $sb;
            $size += 4 + $n;
        }
    }

    if ($body === '') {
        return "\0\0\0\0";
    }
    return pack('V', $size) . $body;
}

$argv0 = (string) ($_SERVER['argv'][0] ?? '');
if (PHP_SAPI === 'cli' && $argv0 !== '' && @realpath($argv0) === realpath(__FILE__)) {
    if (($argc ?? 0) < 2) {
        fwrite(STDERR, "Usage: php bof_loader.php <file.o> [args...]\n");
        fwrite(STDERR, "  Raw token → narrow Beacon str; BOFs needing bof_pack \"Z\" need wstr:C:\\\\path.\n");
        fwrite(STDERR, "  Typed: str:S, wstr:S, int:N, short:N, bin:BASE64 (str/wstr strip quotes; C:/ → C:\\\\).\n");
        fwrite(STDERR, "  Legacy: one argument of even-length hex → raw packed bytes.\n");
        exit(1);
    }
    $path = $argv[1];
    $argTokens = array_slice($argv, 2);

    $loader = new CoffLoader();
    $img = $loader->load($path, []);
    if ($img['go'] === null || $img['goVa'] === null) {
        fwrite(STDERR, "No go/_go symbol found; loaded image at base.\n");
        exit(0);
    }

    $pack = bofCliBuildArgpack($argTokens);
    if ($pack === '') {
        fwrite(STDERR, "Invalid argument payload (typed value or base64 error).\n");
        exit(1);
    }

    $len = strlen($pack);
    $buf = FFI::new("char[{$len}]");
    FFI::memcpy($buf, $pack, $len);
    $loader->runGoInWorkerThread((int) $img['goVa'], $buf, $len);
}
