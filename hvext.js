"use strict";
let PHYSICAL_ADDRESS_WIDTH_SUPPORTED = 48;
let MASK_MAXPHYADDR_52_BIT = host.parseInt64(0xFFFFFFFFFFFFF);
let MASK_1GB_PAGE = host.parseInt64(0x3FFFFFFF);
let MASK_2MB_PAGE = host.parseInt64(0x1FFFFF);
let MASK_12BIT = host.parseInt64(0xFFF);

// Registers commands.
function initializeScript() {
    return [
        new host.apiVersionSupport(1, 7),
        new host.functionAlias(hvextHelp, "hvext_help"),
        new host.functionAlias(dumpDmar, "dump_dmar"),
        new host.functionAlias(dumpEpt, "dump_ept"),
        new host.functionAlias(dumpHlat, "dump_hlat"),
        new host.functionAlias(dumpIo, "dump_io"),
        new host.functionAlias(dumpMsr, "dump_msr"),
        new host.functionAlias(dumpVmcs, "dump_vmcs"),
        new host.functionAlias(eptPte, "ept_pte"),
        new host.functionAlias(indexesFor, "indexes"),
        new host.functionAlias(pte, "pte"),
        new host.functionAlias(gvaTohpa, "gva_to_hpa"),
        new host.functionAlias(readVmcsField, "read_vmcs"),
    ];
}

// Cache of fully-parsed EPT, keyed by EPTP.
let g_eptCache = {};

// Cache of unparsed HLAT tables, keyed by an address of the tables.
let g_hlatCache = {};

// The virtual address of (the first) "VMREAD RAX, RAX" in the HV image range.
let g_vmreadAddress = null;

// Initializes the extension.
function invokeScript() {
    exec(".load kext");
    g_vmreadAddress = findFirstVmreadRaxRax();
    println("hvext loaded. Execute !hvext_help [command] for help.");

    // Returns the first virtual address with "VMREAD RAX, RAX" in the HV address range.
    function findFirstVmreadRaxRax() {
        const isVmreadRaxRax = (memory, i) => (
            memory[i] == 0x0f &&
            memory[i + 1] == 0x78 &&
            memory[i + 2] == 0xc0
        );

        // Search each page in the HV image range. Returns the first hit.
        let hvImageRange = findHvImageRange();
        for (let i = hvImageRange.Start; i.compareTo(hvImageRange.End) == -1; i = i.add(0x1000)) {
            let found = searchMemory(i, 0x1000, isVmreadRaxRax);
            if (found.length != 0) {
                return found[0];
            }
        }
        throw new Error("No VMREAD RAX, RAX (0f 78 c0) found.");

        // Returns the range of the virtual address where the HV image is mapped.
        function findHvImageRange() {
            // Get the range with "lm".
            // eg: fffff876`b89e0000 fffff876`b8de2000   hv         (no symbols)
            let chunks = exec("lm m hv").Last().split(" ");
            let start = chunks[0].replace("`", "");
            let end = chunks[1].replace("`", "");
            return {
                "Start": host.parseInt64(start, 16),
                "End": host.parseInt64(end, 16),
            };
        }

        // Finds an array of virtual addresses that matches the specified condition.
        function searchMemory(address, bytes, predicate) {
            // Memory read can fail if the address is not mapped.
            try {
                var memory = host.memory.readMemoryValues(address, bytes);
            } catch (error) {
                return [];
            }

            let index = [];
            for (let i = 0; i < bytes; i++) {
                if (predicate(memory, i)) {
                    index.push(address.add(i));
                }
            }
            return index;
        }
    }
}

// Implements the !hvext_help command.
function hvextHelp(command) {
    switch (command) {
        case "dump_dmar":
            println("dump_dmar [pa] - Displays status and configurations of a DMA remapping unit.");
            println("   pa - The PA of a DMAR remapping unit. It can be found in the DMAR ACPI table.");
            break;
        case "dump_ept":
            println("dump_ept [verbosity] - Displays guest physical address translation managed through EPT.");
            println("   verbosity - 0 = Shows valid translations in a summarized format (default).");
            println("               1 = Shows both valid and invalid translations in a summarized format.");
            println("               2 = Shows every valid translations without summarizing it.");
            break;
        case "dump_hlat":
            println("dump_hlat [verbosity] - Displays linear address translation managed through HLAT.");
            println("   verbosity - 0 = Shows valid translations in a summarized format (default).");
            println("               1 = Shows both valid and invalid translations in a summarized format.");
            println("               2 = Shows every valid translations without summarizing it.");
            break;
        case "dump_io":
            println("dump_io - Displays contents of the IO bitmaps.");
            break;
        case "dump_msr":
            println("dump_msr [verbosity] - Displays contents of the MSR bitmaps.");
            println("   verbosity - 0 = Shows only MSRs that are not read or write protected (default).");
            println("               1 = Shows protections of all MSRs managed by the MSR bitmaps.");
            break;
        case "dump_vmcs":
            println("dump_vmcs - Displays contents of the current VMCS.");
            break;
        case "ept_pte":
            println("ept_pte [gpa] - Displays contents of EPT entries used to translated the given GPA");
            println("   gpa - A GPA to translate with EPT (default= 0).");
            break;
        case "indexes":
            println("indexes [address] - Displays index values to walk paging structures for the given address.");
            println("   address - An address to decode (default= 0).");
            break;
        case "pte":
            println("pte [la] - Displays contents of paging structure entries used to translated the given LA.");
            println("   la - A LA to translate with the paging structures (default= 0).");
            break;
        case "gva_to_hpa":
            println("gva_to_hpa [gva] - Displays contents of paging structure entries used to translated the given GVA to HPA.");
            println("   gva - A guest virtual address");
            println("   Usage: !gva_to_hpa 0xfffff80258e5db28");
            break;
        case "read_vmcs":
            println("read_vmcs [vmcs_field] - Displays contents of the given VMCS field (encoding) value or name (case insensitive) from the current VMCS.");
            println("   vmcs_field - A VMCS field encoding value or name (case insensitive).");
            println("   Usage: !read_vmcs \"GUEST_CR3\" or !read_vmcs 0x6802")
            break;
        case undefined:
        default:
            println("hvext_help [command] - Displays this message.");
            println("dump_dmar [pa] - Displays status and configurations of a DMA remapping unit.");
            println("dump_ept [verbosity] - Displays guest physical address translation managed through EPT.");
            println("dump_hlat [verbosity] - Displays linear address translation managed through HLAT.");
            println("dump_io - Displays contents of the IO bitmaps.");
            println("dump_msr [verbosity] - Displays contents of the MSR bitmaps.");
            println("dump_vmcs - Displays contents of the current VMCS.");
            println("ept_pte [gpa] - Displays contents of EPT entries used to translated the given GPA.");
            println("indexes [address] - Displays index values to walk paging structures for the given address.");
            println("pte [la] - Displays contents of paging structure entries used to translated the given LA.");
            println("gva_to_hpa [gva] - Displays contents of paging structure entries used to translated the given GVA to HPA.");
            println("read_vmcs [vmcs_field] - Displays contents of the given VMCS field (encoding) value\\name from the current VMCS.");
            println("");
            println("Note: When executing some of those commands, the processor must be in VMX-root operation with an active VMCS.");
            break;
    }
}

// Implements the !dump_dmar command.
function dumpDmar(baseAddr, verbosity) {
    // See: 9.1 Root Entry
    class RootEntry {
        constructor(bus, low64, _high64) {
            // The higher 64 bits are "Reserved".
            this.value = low64;
            this.bus = bus;
            this.present = bits(low64, 0, 1);
            this.contextTablePointer = low64.bitwiseAnd(~0xfff);
            this.contextEntries = [];
        }
    }

    // See: 9.3 Context Entry
    class ContextEntry {
        constructor(device, func, low64, high64) {
            this.value = low64;
            this.device = device;
            this.func = func;
            this.present = bits(low64, 0, 1);
            this.translationType = bits(low64, 2, 2);
            this.ssptPointer = (this.translationType == 0b10) ? "Passthrough" : low64.bitwiseAnd(~0xfff);
            this.domainId = bits(high64, 9, 16);
        }
    }

    class DeviceTranslation {
        constructor(rootEntry, contextEntry) {
            this.bus = (rootEntry) ? rootEntry.bus : 0;
            this.device = (contextEntry) ? contextEntry.device : 0;
            this.func = (contextEntry) ? contextEntry.func : 0;
            this.passthrough = (contextEntry) ? (contextEntry.translationType == 0b10) : false;
            this.ssptPointer = (contextEntry) ? contextEntry.ssptPointer : 0;
        }

        toString() {
            return (this.passthrough ? "Passthrough" : hex(this.ssptPointer)) + " - " + this.bdf();
        }

        bdf() {
            return "B" + this.bus + ",D" + this.device + ",F" + this.func;
        }
    }

    if (baseAddr === undefined) {
        println("Specify a physical address of the remapping hardware unit. " +
            "It is typically 0xfed90000 and 0xfed91000 but may vary between models.");
        return;
    }

    if (verbosity === undefined) {
        verbosity = 0;
    }

    // Read remapping hardware registers.
    // See: 11.4 Register Descriptions
    //
    // 2: kd> !dq 0xfed90000 l6
    // #fed90000 00000000`00000010 01c0000c`40660462
    // #fed90010 0000019e`2ff0505e c7000000`00000000
    // #fed90020 00000001`044fe000 08000000`00000000
    let qwords = [];
    parseEach16Bytes(baseAddr.bitwiseAnd(~0xfff), 3, (l, h) => qwords.push(l, h));
    let version = qwords[0];                // 11.4.1 Version Register
    let capability = qwords[1];             // 11.4.2 Capability Register
    let capabilityEx = qwords[2];           // 11.4.3 Extended Capability Register
    let status = bits(qwords[3], 32, 32);   // 11.4.4 Global Command Interface Registers
    let rootTableAddr = qwords[4];          // 11.4.5 Root Table Address Register
    println("Remapping unit at " + hex(baseAddr));
    println("  version: " + bits(version, 4, 4) + "." + bits(version, 0, 4));
    println("  capability: " + hex(capability));
    println("  extended capability: " + hex(capabilityEx));
    println("  status: " + hex(status));
    println("  root table address: " + hex(rootTableAddr));
    println("");

    // Bail if DMA remapping is not enabled.
    let translationEnableStatus = bits(status, 31, 1);
    if (translationEnableStatus == 0) {
        println("DMA remapping is not enabled.");
        return;
    }

    // Bail if not in the legacy translation mode.
    let translationTableMode = bits(rootTableAddr, 10, 2);
    if (translationTableMode != 0b00) {
        println("Unsupported TTM.");
        return;
    }

    // Parse the root table.
    // See: 3.4.2 Legacy Mode Address Translation
    let rootEntries = [];
    parseEach16Bytes(rootTableAddr.bitwiseAnd(~0xfff), 0x100, (l, h) =>
        rootEntries.push(new RootEntry(rootEntries.length, l, h)));

    // Parse the context tables referenced from the root entries.
    // See: 3.4.2 Legacy Mode Address Translation
    for (let rootEntry of rootEntries) {
        parseEach16Bytes(rootEntry.contextTablePointer, 0x100, (l, h) =>
            rootEntry.contextEntries.push(new ContextEntry(
                bits(rootEntry.contextEntries.length, 3, 5),
                bits(rootEntry.contextEntries.length, 0, 3),
                l,
                h)));
    }

    // First, print which BDF is translated with which second stage page table
    // (SSPT) structures. There are 65536 BDFs, but only a handful of SSPTs are
    // used. So, summarize relation and gather the SSPTs into `ssptPointers`.
    println("Translation   Device");
    let ssptPointers = [];
    let start = new DeviceTranslation();
    let previous = new DeviceTranslation();
    for (let rootEntry of rootEntries) {
        for (let contextEntry of rootEntry.contextEntries) {
            let current = new DeviceTranslation(rootEntry, contextEntry);

            // If the current entry points to a different SSPT than before...
            if (current.ssptPointer != start.ssptPointer) {
                // Print it out (except the very first entry).
                if (start.ssptPointer != 0) {
                    if (start == previous) {
                        println(previous);
                    } else {
                        println(start + " .. " + previous.bdf());
                    }
                }

                // Save the SSPT except when it is pass-through, and record the
                // current entry as a new start.
                if (!current.passthrough) {
                    ssptPointers.push(current.ssptPointer);
                }
                start = current;
            }
            previous = current;
        }
    }
    // Print the last entry.
    if (start == previous) {
        println(previous);
    } else {
        println(start + " .. " + previous.bdf());
    }

    // Dump the all unique SSPTs. SSPTs have the same format as the EPT entries.
    for (let ssptPointer of Array.from(new Set(ssptPointers))) {
        println("");
        println("Dumping second stage page tables at " + hex(ssptPointer));
        dumpEpt(verbosity, getEptPml4(ssptPointer));
    }
}

// Implements the !dump_ept command.
function dumpEpt(verbosity = 0, pml4) {
    class Region {
        constructor(gpa, pa, flags, size) {
            this.gpa = gpa;
            this.pa = pa;
            this.flags = flags;
            this.size = size;
            this.identifyMapping = (gpa == pa);
        }

        toString() {
            // If this is identify mapping, display so instead of actual PA.
            let translation = (this.identifyMapping) ?
                "Identity".padEnd(12) :
                hex(this.pa).padStart(12);

            return hex(this.gpa).padStart(12) + " - " +
                hex(this.gpa + this.size).padStart(12) + " -> " +
                translation + " " +
                this.flags;
        }
    }

    const SIZE_4KB = 0x1000;
    const SIZE_2MB = 0x200000;
    const SIZE_1GB = 0x40000000;
    const SIZE_512GB = 0x8000000000;

    if (pml4 === undefined) {
        pml4 = getCurrentEptPml4();
    }

    // Walk through all EPT entries and accumulate them as regions.
    let regions = [];
    for (let gpa = 0, page_size = 0; ; gpa += page_size) {
        let indexFor = indexesFor(gpa);
        let i1 = indexFor.Pt;
        let i2 = indexFor.Pd;
        let i3 = indexFor.Pdpt;
        let i4 = indexFor.Pml4;

        // Exit once GPA exceeds its max value (48bit-width).
        if (gpa > 0xfffffffff000) {
            break;
        }

        // Pick and check PML4e.
        page_size = SIZE_512GB;
        let pml4e = pml4.entries[i4];
        if (!pml4e.flags.present()) {
            continue;
        }

        // Pick and check PDPTe.
        page_size = SIZE_1GB;
        let pdpt = pml4e.nextTable;
        let pdpte = pdpt.entries[i3];
        if (!pdpte.flags.present()) {
            continue;
        }

        if (pdpte.flags.large) {
            let flags = getEffectiveFlags(pml4e, pdpte);
            regions.push(new Region(gpa, pdpte.pfn.bitwiseShiftLeft(12), flags, page_size));
            continue;
        }

        // Pick and check PDe.
        page_size = SIZE_2MB;
        let pd = pdpte.nextTable;
        let pde = pd.entries[i2];
        if (!pde.flags.present()) {
            continue;
        }

        if (pde.flags.large) {
            let flags = getEffectiveFlags(pml4e, pdpte, pde);
            regions.push(new Region(gpa, pde.pfn.bitwiseShiftLeft(12), flags, page_size));
            continue;
        }

        // Pick and check PTe.
        page_size = SIZE_4KB;
        let pt = pde.nextTable;
        let pte = pt.entries[i1];
        if (!pte.flags.present()) {
            continue;
        }

        let flags = getEffectiveFlags(pml4e, pdpte, pde, pte);
        regions.push(new Region(gpa, pte.pfn.bitwiseShiftLeft(12), flags, page_size));
    }

    // Display gathered regions.
    println("GPA [begin, end)               PA           Flags");
    if (verbosity > 1) {
        // Just dump all regions.
        regions.map(println);
    } else {
        // Combine regions that are effectively contiguous.
        let combined_region = null;
        for (let region of regions) {
            if (combined_region === null) {
                combined_region = region;
                continue;
            }

            // Is this region contiguous to the current region? That is, both
            // identify mapped, have the same flags and corresponding GPAs are
            // contiguous.
            if (combined_region.identifyMapping &&
                region.identifyMapping &&
                combined_region.flags.toString() == region.flags.toString() &&
                combined_region.gpa + combined_region.size == region.gpa) {
                // It is contiguous. Just expand the size.
                combined_region.size += region.size;
            } else {
                // It is not contiguous. Display the current region.
                println(combined_region);

                // See if there is an unmapped regions before this region.
                if (verbosity > 0 &&
                    combined_region.gpa + combined_region.size != region.gpa) {
                    //  Yes, there is. Display that.
                    let unmapped_base = combined_region.gpa + combined_region.size;
                    let unmapped_size = region.gpa - unmapped_base;
                    println(hex(unmapped_base).padStart(12) + " - " +
                        hex(unmapped_base + unmapped_size).padStart(12) + " -> " +
                        "Unmapped".padEnd(12) + " " +
                        new EptFlags(0));
                }

                // Move on, and start checking contiguous regions from this region.
                combined_region = region;
            }
        }

        // Display the last one.
        println(combined_region);
    }

    // Computes the effective flag value from the given EPT entries. The large bit
    // is always reported as 0.
    function getEffectiveFlags(pml4e, pdpte, pde, pte) {
        let flags = new EptFlags(0);
        flags.read = pml4e.flags.read & pdpte.flags.read;
        flags.write = pml4e.flags.write & pdpte.flags.write;
        flags.execute = pml4e.flags.execute & pdpte.flags.execute;
        flags.executeForUserMode = pml4e.flags.executeForUserMode & pdpte.flags.executeForUserMode;

        let leaf = pdpte;
        if (pde) {
            leaf = pde;
            flags.read &= pde.flags.read;
            flags.write &= pde.flags.write;
            flags.execute &= pde.flags.execute;
            flags.executeForUserMode &= pde.flags.executeForUserMode;
        }
        if (pte) {
            leaf = pte;
            flags.read &= pte.flags.read;
            flags.write &= pte.flags.write;
            flags.execute &= pte.flags.execute;
            flags.executeForUserMode &= pte.flags.executeForUserMode;
        }
        flags.memoryType = leaf.flags.memoryType;
        flags.verifyGuestPaging = leaf.flags.verifyGuestPaging;
        flags.pagingWriteAccess = leaf.flags.pagingWriteAccess;
        flags.supervisorShadowStack = leaf.flags.supervisorShadowStack;
        return flags;
    }
}

// Implements the !dump_hlat command.
function dumpHlat(verbosity = 0, pml4) {
    class Region {
        constructor(la, gpa, flags, size) {
            this.la = la;
            this.gpa = gpa;  // `undefined` if unmapped.
            this.flags = flags;
            this.size = size;
            this.identifyMapping = (la == gpa);
        }

        toString() {
            // If this is identify mapping or unmapped, display so.
            let translation = (this.identifyMapping) ?
                "Identity".padEnd(12) :
                (!this.flags.present()) ?
                    "Unmapped".padEnd(12) :
                    hex(this.gpa).padStart(12);

            return hex(this.la).padStart(12) + " - " +
                hex(this.la.add(this.size)).padStart(12) + " -> " +
                translation + " " +
                this.flags;
        }
    }

    const SIZE_4KB = 0x1000;
    const SIZE_2MB = 0x200000;
    const SIZE_1GB = 0x40000000;
    const SIZE_512GB = 0x8000000000;

    if (pml4 === undefined) {
        pml4 = getCurrentHlatPml4();
    }

    // If the HLAT prefix size is 1, HLAT is enabled for only linear addresses
    // where the bit 63 of them is 1 (ake, kernel addresses). Windows only uses
    // this setup, so we support only this too.
    let hlat_prefix_size = readVmcs(0x00000006); // HLAT prefix size
    if (hlat_prefix_size != 1) {
        throw new Error("Unsupported HLAT prefix size: " + hlat_prefix_size);
    }

    // A set of empty tables to speed up parsing.
    let emptyTableCache = new Set();

    // Walk through all HLAT entries and accumulate them as regions. We start at
    // 0xffff800000000000, the lowest canonical form address that HLAT page walk
    // can happen when the HLAT prefix size is 1.
    let regions = [];
    let la = host.Int64(0xffff800000000000);
    let indexFor = indexesFor(la);
    for (let i4 = indexFor.Pml4; i4 < 512; i4++, la = la.add(SIZE_512GB)) {
        let pml4e = pml4.entries[i4];
        if (!pml4e.flags.present()) {
            regions.push(new Region(la, undefined, new PsFlags(0), SIZE_512GB));
            continue;
        }

        if (pml4e.flags.restart) {
            continue;
        }

        let pdpt = pml4e.nextTable;
        if (emptyTableCache.has(pdpt)) {
            continue;
        }

        if (parsePdpt(indexFor, pdpt, la, regions, pml4e)) {
            emptyTableCache.add(pdpt);
        }
    }

    println("LA [begin, end)                             GPA         Flags");
    if (verbosity > 1) {
        // Dump all regions with valid translations.
        regions.map((region) => {
            if (region.flags.present()) {
                println(region);
            }
        });
    } else {
        // Combine regions that are effectively contiguous.
        let combined_region = null;
        for (let region of regions) {
            if (combined_region === null) {
                combined_region = region;
                continue;
            }

            // Is this region contiguous to the current region? That is, ...
            if (combined_region.flags.toString() == region.flags.toString() &&
                combined_region.la.add(combined_region.size) == region.la &&
                ((!combined_region.flags.present() && !region.flags.present()) ||
                    (combined_region.flags.present() && region.flags.present() &&
                        combined_region.gpa.add(combined_region.size) == region.gpa))) {
                // It is contiguous. Just expand the size.
                combined_region.size += region.size;
            } else {
                // It is not contiguous. Display the current region if it is valid,
                // or in a verbose mode.
                if (combined_region.flags.present() || verbosity > 0) {
                    println(combined_region);
                }

                // If not, see if there is a restarted regions before this region.
                if (verbosity > 0 &&
                    combined_region.la.add(combined_region.size) != region.la) {
                    //  Yes, there is. Display that.
                    let missing_region_base = combined_region.la.add(combined_region.size);
                    let missing_region_size = region.la.subtract(missing_region_base);
                    println(hex(missing_region_base).padStart(12) + " - " +
                        hex(missing_region_base.add(missing_region_size)).padStart(12) + " -> " +
                        "Restart".padEnd(12) + " " +
                        new PsFlags(0));
                }

                // Move on, and start checking contiguous regions from this region.
                combined_region = region;
            }
        }

        // Display the last one.
        if (combined_region.flags.present() || verbosity > 0) {
            println(combined_region);
        }
    }

    /// Parses HLAT PDPT and accumulates region information into `regions`.
    /// Returns true if no entry with a valid translation exists in the table.
    /// "Valid" in this context excludes pages that are marked as "restart" and
    /// "not-present".
    function parsePdpt(indexFor, pdpt, la, regions, pml4e) {
        let empty = true;
        for (let i3 = indexFor.Pdpt; i3 < 512; i3++, la = la.add(SIZE_1GB)) {
            let pdpte = pdpt.entries[i3];
            if (!pdpte.flags.present()) {
                regions.push(new Region(la, undefined, new PsFlags(0), SIZE_1GB));
                continue;
            }
            if (pdpte.flags.restart) {
                continue;
            }
            if (pdpte.flags.large) {
                let flags = getEffectiveFlags(pml4e, pdpte);
                regions.push(new Region(la, pdpte.pfn.bitwiseShiftLeft(12), flags, SIZE_1GB));
                empty = false;
                continue;
            }
            let pd = pdpte.nextTable;
            if (emptyTableCache.has(pd)) {
                continue;
            }

            if (parsePd(indexFor, pd, la, regions, pml4e, pdpte)) {
                emptyTableCache.add(pd);
            } else {
                empty = false;
            }
        }
        return empty;
    }

    /// Parses HLAT PD. See parsePdpt for more details.
    function parsePd(indexFor, pd, la, regions, pml4e, pdpte) {
        let empty = true;
        for (let i2 = indexFor.Pd; i2 < 512; i2++, la = la.add(SIZE_2MB)) {
            let pde = pd.entries[i2];
            if (!pde.flags.present()) {
                regions.push(new Region(la, undefined, new PsFlags(0), SIZE_2MB));
                continue;
            }
            if (pde.flags.restart) {
                continue;
            }
            if (pde.flags.large) {
                let flags = getEffectiveFlags(pml4e, pdpte, pde);
                regions.push(new Region(la, pde.pfn.bitwiseShiftLeft(12), flags, SIZE_2MB));
                empty = false;
                continue;
            }
            let pt = pde.nextTable;
            if (emptyTableCache.has(pt)) {
                continue;
            }

            if (parsePt(indexFor, pt, la, regions, pml4e, pdpte, pde)) {
                emptyTableCache.add(pt);
            } else {
                empty = false;
            }
        }
        return empty;
    }

    /// Parses HLAT PT. See parsePdpt for more details.
    function parsePt(indexFor, pt, la, regions, pml4e, pdpte, pde) {
        let empty = true;
        for (let i1 = indexFor.Pt; i1 < 512; i1++, la = la.add(SIZE_4KB)) {
            let pte = pt.entries[i1];
            if (!pte.flags.present()) {
                regions.push(new Region(la, undefined, new PsFlags(0), SIZE_4KB));
                continue;
            }
            if (pte.flags.restart) {
                continue;
            }

            let flags = getEffectiveFlags(pml4e, pdpte, pde, pte);
            regions.push(new Region(la, pte.pfn.bitwiseShiftLeft(12), flags, SIZE_4KB));
            empty = false;
        }
        return empty;
    }

    // Computes the effective flag value from the given PS entries. The accessed,
    // dirty, large, restart bits are always reported as 0.
    function getEffectiveFlags(pml4e, pdpte, pde, pte) {
        let flags = new PsFlags(0);
        flags.valid = pml4e.flags.valid & pdpte.flags.valid;
        flags.write = pml4e.flags.write & pdpte.flags.write;
        flags.user = pml4e.flags.user & pdpte.flags.user;
        flags.nonExecute = pml4e.flags.nonExecute | pdpte.flags.nonExecute;

        let leaf = pdpte;
        if (pde) {
            leaf = pde;
            flags.valid &= pde.flags.valid;
            flags.write &= pde.flags.write;
            flags.user &= pde.flags.user;
            flags.nonExecute |= pde.flags.nonExecute;
        }
        if (pte) {
            leaf = pte;
            flags.valid &= pte.flags.valid;
            flags.write &= pte.flags.write;
            flags.user &= pte.flags.user;
            flags.nonExecute |= pte.flags.nonExecute;
        }
        return flags;
    }
}

// Returns fully-parsed HLAT entries pointed by the current HLATP VMCS encoding.
function getCurrentHlatPml4() {
    let exec_control1 = readVmcs(0x00004002);    // Primary processor-based VM-execution controls
    if (bits(exec_control1, 17, 1) == 0) {
        throw new Error("HLAT is not enabled");
    }

    let exec_control3 = readVmcs(0x00002034);    // Tertiary processor-based VM-execution controls
    if (bits(exec_control3, 1, 1) == 0) {
        throw new Error("HLAT is not enabled");
    }

    let hlatp = readVmcs(0x00002040);  // Hypervisor-managed linear-address translation pointer
    if (hlatp === undefined) {
        throw new Error("The VMREAD instruction failed");
    }

    println("Current HLAT pointer " + hex(hlatp));
    return new HlatPml4(hlatp.bitwiseAnd(~0xfff));
}

// Implements the !dump_io command.
function dumpIo() {
    class IoAccessibilityRange {
        constructor(begin = undefined, end = undefined, intercepted = undefined) {
            this.begin = begin;
            this.end = end;
            this.intercepted = intercepted;
        }

        toString() {
            return (this.intercepted ? "-- " : "RW ") + hex(this.begin) +
                (this.begin == this.end ? "" : " .. " + hex(this.end));
        }
    }

    let exec_control = readVmcs(0x00004002);    // Primary processor-based VM-execution controls
    if (bits(exec_control, 25, 1) == 0) {
        // Check "unconditional I/O exiting"
        if (bits(exec_control, 24, 1) == 0) {
            println("IO bitmaps are not used. IO port access does not cause VM-exit.");
        } else {
            println("IO port access unconditionally causes VM-exit.");
        }
        return;
    }

    let bitmap_low = readVmcs(0x00002000);  // I/O bitmap A
    let bitmap_high = readVmcs(0x00002002);  // I/O bitmap B

    // Convert the 4KB contents into an array of 64bit integers for processing.
    let entries = [];
    parseEach16Bytes(bitmap_low, 0x100, (l, h) => entries.push(l, h));
    parseEach16Bytes(bitmap_high, 0x100, (l, h) => entries.push(l, h));

    let ranges = [];
    let range = undefined;
    let port = 0;
    for (let entry of entries) {
        for (let bit_position = 0; bit_position < 64; bit_position++, port++) {
            let intercepted = bits(entry, bit_position, 1);
            if (port == 0) {
                range = new IoAccessibilityRange(port, port, intercepted);
            } else if (range.intercepted == intercepted) {
                // Interception status remained same. Just extend the range.
                range.end = port;
            } else {
                // Interception status changed. Save the range and start a new one.
                ranges.push(range);
                range = new IoAccessibilityRange(port, port, intercepted);
            }
        }
    }
    ranges.push(range);
    ranges.map(println);
}

// Implements the !dump_msr command.
function dumpMsr(verbosity = 0) {
    class MsrEntry {
        constructor(bit_position, read_protected, write_protected) {
            if (bit_position < 0x2000) {
                this.msr = bit_position;
            } else {
                this.msr = bit_position - 0x2000 + 0xc0000000;
            }
            this.read_protected = read_protected;
            this.write_protected = write_protected;
        }

        toString() {
            return (
                { 1: "-", 0: "R" }[this.read_protected] +
                { 1: "-", 0: "W" }[this.write_protected] +
                " " +
                hex(this.msr)
            );
        }
    }

    let exec_control = readVmcs(0x00004002);    // Primary processor-based VM-execution controls
    if (bits(exec_control, 28, 1) == 0) {
        println("MSR bitmaps are not used. MSR access unconditionally causes VM-exit.");
        return;
    }

    let bitmap = readVmcs(0x00002004);  // MSR bitmaps

    // Convert the 4KB contents into an array of 64bit integers for processing.
    let entries = [];
    parseEach16Bytes(bitmap.bitwiseAnd(~0xfff), 0x100, (l, h) => entries.push(l, h));

    // The MSR bitmaps are made up of two 2048 bytes segments. The first segment
    // manages read access, and the 2nd manages write access, for the same ranges
    // of MSRs. Let us walk the half of the `entries` and add offset 2048
    // (= 0x100 * 8) to look both segments in a single loop.
    let msrs = [];
    for (let i = 0; i < 0x100; i++) {
        let entry_low = entries[i];
        let entry_hi = entries[i + 0x100];
        // For the selected upper and lower 64bit entries, walk though each bit
        // position and construct `MsrEntry` from the pair of the bits.
        for (let bit_position = 0; bit_position < 64; bit_position++) {
            let read_protected = bits(entry_low, bit_position, 1);
            let write_protected = bits(entry_hi, bit_position, 1);
            msrs.push(new MsrEntry(i * 64 + bit_position, read_protected, write_protected));
        }
    }

    for (let msr of msrs) {
        if (verbosity == 0) {
            if (!msr.read_protected || !msr.write_protected) {
                println(msr);
            }
        } else {
            println(msr);
        }
    }
}

// Implements the !dump_vmcs command.
function dumpVmcs() {
    // Capture the current state.
    // eg: efl=00000242 rax=0000000000006c1c rip=fffff813d4f00ea1
    let output = exec("r efl, rax, rip").Last();
    let originalRflags = output.substring(4, 12);
    let originalRax = output.substring(17, 33);
    let originalRip = output.substring(38, 54);

    // Loop over the VMCS encodings.
    for (let i = 0; i < VMCS_ENCODINGS.length; i += 2) {
        let name = VMCS_ENCODINGS[i];
        let encoding = VMCS_ENCODINGS[i + 1];
        let value = readVmcsUnsafe(encoding);
        if (value === undefined) {
            println("***** FAILED *****" + " " + name);
        } else {
            println(hex(value, 16) + " " + name);
        }
    }

    // All done. Restore the original state.
    exec("r rax=" + originalRax + ", " +
        "rip=" + originalRip + ", " +
        "efl=" + originalRflags);
}

// Implements the !read_vmcs command.
function readVmcsField(input) {
    let encoding = null;
    let vmcs_field_name = "";

    if (typeof input === "string") {
        // println("Input name provided:", input);
        // Assume it's a name, look up the corresponding encoding
        for (let i = 0; i < VMCS_ENCODINGS.length; i += 2) {
            if (VMCS_ENCODINGS[i].toLowerCase() === input.toLowerCase()) {
                vmcs_field_name = VMCS_ENCODINGS[i];
                encoding = VMCS_ENCODINGS[i + 1];
                break;
            }
        }

        if (encoding === null) {
            println("Error: Unable to find encoding name '" + input + "'");
            return;
        }
    } else if (typeof input === "number") {
        // Handle input as an integer (could be a direct hexadecimal value)
        encoding = input;

        // Check if the encoding value exists in the VMCS_ENCODINGS array
        let encodingExists = false;
        for (let i = 1; i < VMCS_ENCODINGS.length; i += 2) {
            if (VMCS_ENCODINGS[i] === encoding) {
                vmcs_field_name = VMCS_ENCODINGS[i-1];
                encodingExists = true;
                break;
            }
        }

        if (!encodingExists) {
            println("Error: Encoding value not found.");
            return;
        }
    } else {
        println("Error: Unexpected input type. Please provide a string or a number.");
        return;
    }
    
    let value = readVmcsUnsafe(encoding);
    if (value === undefined) {
        println("***** FAILED *****" + " " + vmcs_field_name);
        println(vmcs_field_name + ": ***** FAILED *****");
    } else {
        println(vmcs_field_name + ": " + hex(value, 16));
    }
}

// Implements the internal version of ept_pte command. (only debug output)
function _eptPte(gpa, pml4) {
    if (gpa === undefined) {
        gpa = 0;
    }

    if (pml4 === undefined) {
        pml4 = getCurrentEptPml4();
    }

    let indexFor = indexesFor(gpa);
    let i1 = indexFor.Pt;
    let i2 = indexFor.Pd;
    let i3 = indexFor.Pdpt;
    let i4 = indexFor.Pml4;

    // Pick and check PML4e.
    let pml4e = pml4.entries[i4];
    if (!pml4e.flags.present()) {
        println("(ept) PML4e is not present" + hex(pml4.address.add(8 * i4)));
        println("(ept) PML4e at " + hex(pml4.address.add(8 * i4)));
        println("contains " + hex(pml4e.value));
        println("pfn " + pml4e);
        return undefined;
    }

    // Pick and check PDPTe.
    let pdpt = pml4e.nextTable;
    let pdpte = pdpt.entries[i3];
    if (!pdpte.flags.present() ) {
        println("(ept) PML4e at " + hex(pml4.address.add(8 * i4)).padEnd(18) +
            "(ept) PDPTe (is not present) at " + hex(pdpt.address.add(8 * i3)));
        println("contains " + hex(pml4e.value).padEnd(18) +
            "contains " + hex(pdpte.value));
        println("pfn " + (pml4e + "").padEnd(23) +
            "pfn " + pdpte);
        return undefined;
    }

    if (pdpte.flags.large) {
        let pfn = pdpte.value
                        .bitwiseAnd(MASK_MAXPHYADDR_52_BIT)
                        .bitwiseShiftRight(30)
                        .bitwiseAnd(host.parseInt64(1)
                        .bitwiseShiftLeft(PHYSICAL_ADDRESS_WIDTH_SUPPORTED - 30)
                        .subtract(1));
        let pa = pfn.bitwiseShiftLeft(30);
        let offset = gpa.bitwiseAnd(MASK_1GB_PAGE);
        return pa.add(offset);
    }

    else{
        // Pick and check PDe.
        let pd = pdpte.nextTable;
        let pde = pd.entries[i2];
        if (!pde.flags.present()) {
            println("(ept) PML4e at " + hex(pml4.address.add(8 * i4)).padEnd(18) +
                "(ept) PDPTe at " + hex(pdpt.address.add(8 * i3)).padEnd(18) +
                "(ept) PDe (is not present) at " + hex(pd.address.add(8 * i2)));
            println("contains " + hex(pml4e.value).padEnd(18) +
                "contains " + hex(pdpte.value).padEnd(18) +
                "contains " + hex(pde.value));
            println("pfn " + (pml4e + "").padEnd(23) +
                "pfn " + (pdpte + "").padEnd(23) +
                "pfn " + pde);
            return undefined;
        }

        if (pde.flags.large) {
            let pfn = pde.value
                            .bitwiseAnd(MASK_MAXPHYADDR_52_BIT)
                            .bitwiseShiftRight(21)
                            .bitwiseAnd(host.parseInt64(1)
                            .bitwiseShiftLeft(PHYSICAL_ADDRESS_WIDTH_SUPPORTED - 21)
                            .subtract(1));
            let pa = pfn.bitwiseShiftLeft(21);
            let offset = gpa.bitwiseAnd(MASK_2MB_PAGE);
            return pa.add(offset);
        }
        else {
            // Pick PTe.
            let pt = pde.nextTable;
            let pte = pt.entries[i1];

            if (!pte.flags.present()) {
                println("(ept) pte is not present");
                return undefined;
            }
            else{
                //println("pte.pfn: " + hex(pte.pfn));
                let pa = pte.pfn.bitwiseShiftLeft(12);
                let offset = gpa.bitwiseAnd(MASK_12BIT);
                //println("pa: " + hex(pa));
                //println("GPA_TO_HPA: " + hex(pa.add(offset)));
                return pa.add(offset);
            }
         }
    }
}

// Implements the !ept_pte command.
function eptPte(gpa, pml4) {
    if (gpa === undefined) {
        gpa = 0;
    }
    if (pml4 === undefined) {
        pml4 = getCurrentEptPml4();
    }

    let indexFor = indexesFor(gpa);
    let i1 = indexFor.Pt;
    let i2 = indexFor.Pd;
    let i3 = indexFor.Pdpt;
    let i4 = indexFor.Pml4;

    // Pick and check PML4e.
    let pml4e = pml4.entries[i4];
    if (!pml4e.flags.present()) {
        println("PML4e at " + hex(pml4.address.add(8 * i4)));
        println("contains " + hex(pml4e.value));
        println("pfn " + pml4e);
        return;
    }

    // Pick and check PDPTe.
    let pdpt = pml4e.nextTable;
    let pdpte = pdpt.entries[i3];
    if (!pdpte.flags.present() || pdpte.flags.large) {
        println("PML4e at " + hex(pml4.address.add(8 * i4)).padEnd(18) +
            "PDPTe at " + hex(pdpt.address.add(8 * i3)));
        println("contains " + hex(pml4e.value).padEnd(18) +
            "contains " + hex(pdpte.value));
        println("pfn " + (pml4e + "").padEnd(23) +
            "pfn " + pdpte);
        return;
    }

    // Pick and check PDe.
    let pd = pdpte.nextTable;
    let pde = pd.entries[i2];
    if (!pde.flags.present() || pde.flags.large) {
        println("PML4e at " + hex(pml4.address.add(8 * i4)).padEnd(18) +
            "PDPTe at " + hex(pdpt.address.add(8 * i3)).padEnd(18) +
            "PDe at " + hex(pd.address.add(8 * i2)));
        println("contains " + hex(pml4e.value).padEnd(18) +
            "contains " + hex(pdpte.value).padEnd(18) +
            "contains " + hex(pde.value));
        println("pfn " + (pml4e + "").padEnd(23) +
            "pfn " + (pdpte + "").padEnd(23) +
            "pfn " + pde);
        return;
    }

    // Pick PTe.
    let pt = pde.nextTable;
    let pte = pt.entries[i1];
    println("PML4e at " + hex(pml4.address.add(8 * i4)).padEnd(18) +
        "PDPTe at " + hex(pdpt.address.add(8 * i3)).padEnd(18) +
        "PDe at " + hex(pd.address.add(8 * i2)).padEnd(20) +
        "PTe at " + hex(pt.address.add(8 * i1)));
    println("contains " + hex(pml4e.value).padEnd(18) +
        "contains " + hex(pdpte.value).padEnd(18) +
        "contains " + hex(pde.value).padEnd(18) +
        "contains " + hex(pte.value));
    println("pfn " + (pml4e + "").padEnd(23) +
        "pfn " + (pdpte + "").padEnd(23) +
        "pfn " + (pde + "").padEnd(23) +
        "pfn " + pte);
}

// Implements the !indexes command.
function indexesFor(address) {
    if (address == undefined) {
        address = 0;
    }

    return {
        "Pt": bits(address, 12, 9),
        "Pd": bits(address, 21, 9),
        "Pdpt": bits(address, 30, 9),
        "Pml4": bits(address, 39, 9),
    };
}

// Implements the !pte command.
function pte(la, pml4) {
    if (la === undefined) {
        la = 0;
    }
    if (pml4 === undefined) {
        pml4 = host.currentThread.Registers.Kernel.cr3.bitwiseAnd(~0xfff);
    }

    let indexFor = indexesFor(la);
    let i1 = indexFor.Pt;
    let i2 = indexFor.Pd;
    let i3 = indexFor.Pdpt;
    let i4 = indexFor.Pml4;

    // Pick and check PML4e.
    let pml4e = new PsEntry(readEntry(pml4 + 8 * i4));
    if (!pml4e.flags.present()) {
        println("PML4e at " + hex(pml4.add(8 * i4)));
        println("contains " + hex(pml4e.value));
        println("pfn " + pml4e);
        return;
    }

    // Pick and check PDPTe.
    let pdpt = pml4e.pfn.bitwiseShiftLeft(12);
    let pdpte = new PsEntry(readEntry(pdpt + 8 * i3));
    if (!pdpte.flags.present() || pdpte.flags.large) {
        println("PML4e at " + hex(pml4.add(8 * i4)).padEnd(18) +
            "PDPTe at " + hex(pdpt.add(8 * i3)));
        println("contains " + hex(pml4e.value).padEnd(18) +
            "contains " + hex(pdpte.value));
        println("pfn " + (pml4e + "").padEnd(23) +
            "pfn " + pdpte);
        return;
    }

    // Pick and check PDe.
    let pd = pdpte.pfn.bitwiseShiftLeft(12);
    let pde = new PsEntry(readEntry(pd + 8 * i2));
    if (!pde.flags.present() || pde.flags.large) {
        println("PML4e at " + hex(pml4.add(8 * i4)).padEnd(18) +
            "PDPTe at " + hex(pdpt.add(8 * i3)).padEnd(18) +
            "PDe at " + hex(pd.add(8 * i2)));
        println("contains " + hex(pml4e.value).padEnd(18) +
            "contains " + hex(pdpte.value).padEnd(18) +
            "contains " + hex(pde.value));
        println("pfn " + (pml4e + "").padEnd(23) +
            "pfn " + (pdpte + "").padEnd(23) +
            "pfn " + pde);
        return;
    }

    // Pick PTe.
    let pt = pde.pfn.bitwiseShiftLeft(12);
    let pte = new PsEntry(readEntry(pt + 8 * i1));
    println("PML4e at " + hex(pml4.add(8 * i4)).padEnd(18) +
        "PDPTe at " + hex(pdpt.add(8 * i3)).padEnd(18) +
        "PDe at " + hex(pd.add(8 * i2)).padEnd(20) +
        "PTe at " + hex(pt.add(8 * i1)));
    println("contains " + hex(pml4e.value).padEnd(18) +
        "contains " + hex(pdpte.value).padEnd(18) +
        "contains " + hex(pde.value).padEnd(18) +
        "contains " + hex(pte.value));
    println("pfn " + (pml4e + "").padEnd(23) +
        "pfn " + (pdpte + "").padEnd(23) +
        "pfn " + (pde + "").padEnd(23) +
        "pfn " + pte);

    function readEntry(address) {
        let line = exec("!dq " + hex(address) + " l1").Last();
        return host.parseInt64(line.replace(/`/g, "").substring(10).trim().split(" "), 16);
    }
}

// Implements the internal version of pte command. (only debug output)
function _pte(va, pml4) {
    if (va === undefined) {
        la = 0;
    }
    if (pml4 === undefined) {
        pml4 = host.currentThread.Registers.Kernel.cr3.bitwiseAnd(~0xfff);
    }

    let indexFor = indexesFor(va);
    let i1 = indexFor.Pt;
    let i2 = indexFor.Pd;
    let i3 = indexFor.Pdpt;
    let i4 = indexFor.Pml4;

    // Pick and check PML4e.
    let pml4e = new PsEntry(readEntry(pml4 + 8 * i4));
    if (!pml4e.flags.present()) {
        println("PML4e is not present");
        println("PML4e at " + hex(pml4.add(8 * i4)));
        println("contains " + hex(pml4e.value));
        println("pfn " + pml4e);
        return;
    }

    // Pick and check PDPTe.
    let pdpt = pml4e.pfn.bitwiseShiftLeft(12);
    let pdpte = new PsEntry(readEntry(pdpt + 8 * i3));
    if (!pdpte.flags.present()) {
        println("PDPTe is not present");
        println("PML4e at " + hex(pml4.add(8 * i4)).padEnd(18) +
            "PDPTe at " + hex(pdpt.add(8 * i3)));
        println("contains " + hex(pml4e.value).padEnd(18) +
            "contains " + hex(pdpte.value));
        println("pfn " + (pml4e + "").padEnd(23) +
            "pfn " + pdpte);
        return;
    }

    if (pdpte.flags.large) {
        let pfn = pdpte.value
                        .bitwiseAnd(MASK_MAXPHYADDR_52_BIT)
                        .bitwiseShiftRight(30)
                        .bitwiseAnd(host.parseInt64(1)
                        .bitwiseShiftLeft(PHYSICAL_ADDRESS_WIDTH_SUPPORTED - 30)
                        .subtract(1));
        let pa = pfn.bitwiseShiftLeft(30);
        let offset = va.bitwiseAnd(MASK_1GB_PAGE);
        println("PTE_VA_TO_PA: " + hex(pa.add(offset)));
        return pa.add(offset);
    }

    else{
        // Pick and check PDe.
        let pd = pdpte.pfn.bitwiseShiftLeft(12);
        let pde = new PsEntry(readEntry(pd + 8 * i2));
        if (!pde.flags.present()) {
            println("PDe is not present");
            println("PML4e at " + hex(pml4.add(8 * i4)).padEnd(18) +
                "PDPTe at " + hex(pdpt.add(8 * i3)).padEnd(18) +
                "PDe at " + hex(pd.add(8 * i2)));
            println("contains " + hex(pml4e.value).padEnd(18) +
                "contains " + hex(pdpte.value).padEnd(18) +
                "contains " + hex(pde.value));
            println("pfn " + (pml4e + "").padEnd(23) +
                "pfn " + (pdpte + "").padEnd(23) +
                "pfn " + pde);
            return;
        }

        if (pde.flags.large) {
            let pfn = pde.value
                            .bitwiseAnd(MASK_MAXPHYADDR_52_BIT)
                            .bitwiseShiftRight(21)
                            .bitwiseAnd(host.parseInt64(1)
                            .bitwiseShiftLeft(PHYSICAL_ADDRESS_WIDTH_SUPPORTED - 21)
                            .subtract(1));
            let pa = pfn.bitwiseShiftLeft(21);
            let offset = va.bitwiseAnd(MASK_2MB_PAGE);
            println("PTE_VA_TO_PA: " + hex(pa.add(offset)));
            return pa.add(offset);
        }
        else{
            // Pick PTe.
            let pt = pde.pfn.bitwiseShiftLeft(12);
            let pte = new PsEntry(readEntry(pt + 8 * i1));

            if (!pte.flags.present()) {
                println("PTe is not present");
                println("PML4e at " + hex(pml4.add(8 * i4)).padEnd(18) +
                "PDPTe at " + hex(pdpt.add(8 * i3)).padEnd(18) +
                "PDe at " + hex(pd.add(8 * i2)).padEnd(20) +
                "PTe at " + hex(pt.add(8 * i1)));
            println("contains " + hex(pml4e.value).padEnd(18) +
                "contains " + hex(pdpte.value).padEnd(18) +
                "contains " + hex(pde.value).padEnd(18) +
                "contains " + hex(pte.value));
            println("pfn " + (pml4e + "").padEnd(23) +
                "pfn " + (pdpte + "").padEnd(23) +
                "pfn " + (pde + "").padEnd(23) +
                "pfn " + pte);
            }
            else{
                //println("pte.pfn: " + hex(pte.pfn));
                let pa = pte.pfn.bitwiseShiftLeft(12);
                let offset = va.bitwiseAnd(MASK_12BIT);
                //println("pa: " + hex(pa));
                println("PTE_VA_TO_PA: " + hex(pa.add(offset)));
                return pa.add(offset);
            }
        }
    }

    function readEntry(address) {
        let line = exec("!dq " + hex(address) + " l1").Last();
        return host.parseInt64(line.replace(/`/g, "").substring(10).trim().split(" "), 16);
    }
}

// Implements the !gva_to_hpa command.
function gvaTohpa(gva) {
    if (gva === undefined) {
        println("Error: 'gva' is undefined");
        return;
    }

    let eptp = getCurrentEptPml4();
    let guest_cr3 = getCurrentGuestCr3();
    
    let guest_cr3_hpa = _eptPte(guest_cr3, eptp);
    if (guest_cr3_hpa === undefined) {
        // error
        println("Error [gvaTohpa] _eptPte(guest_cr3, eptp)");
        return;
    }
    else{
        println("GUEST_CR3 (GPA, " + hex(guest_cr3) + ") to HPA: " + hex(guest_cr3_hpa));
    }

    let b_identity_mapping = (guest_cr3 == guest_cr3_hpa)

    if (b_identity_mapping) {
        println("GUEST_CR3 GPA = GUEST_CR3 HPA (identity-mapping)")
        _pte(gva, guest_cr3_hpa);
    }

    else{
        let indexFor = indexesFor(gva);
        let i1 = indexFor.Pt;
        let i2 = indexFor.Pd;
        let i3 = indexFor.Pdpt;
        let i4 = indexFor.Pml4;
        
        // read pml4e entry - GPA
        // Pick and check PML4e.
        let pml4e_gpa = new PsEntry(readEntry(guest_cr3_hpa + 8 * i4));
        if (!pml4e_gpa.flags.present()) {
            println("PML4e is not present");
            return;
        }

        let pml4e_hpa = _eptPte(pml4e_gpa.pfn.bitwiseShiftLeft(12), eptp);
        if (pml4e_hpa === undefined) {
            println("Error [gvaTohpa] _eptPte(pml4e_gpa, eptp)");
            return;
        }

        // read pdpte entry - GPA
        // Pick and check PDPTe.
        let pdpte_gpa = new PsEntry(readEntry(pml4e_hpa + 8 * i3));
        if (!pdpte_gpa.flags.present()) {
            println("PDPTe is not present");
            return;
        }

        // handle PDPTe Large page
        if (pdpte_gpa.flags.large) {
            let pfn = pdpte_gpa.value
                            .bitwiseAnd(MASK_MAXPHYADDR_52_BIT)
                            .bitwiseShiftRight(30)
                            .bitwiseAnd(host.parseInt64(1)
                            .bitwiseShiftLeft(PHYSICAL_ADDRESS_WIDTH_SUPPORTED - 30)
                            .subtract(1));
            let pa = pfn.bitwiseShiftLeft(30);
            let offset = gva.bitwiseAnd(MASK_1GB_PAGE);
            let guest_gpa = pa.add(offset);
            let host_hpa = _eptPte(guest_gpa, eptp);
            println("GVA: " + hex(gva) + ", GPA: " + hex(guest_gpa) + ", HPA: " + hex(host_hpa));
            return host_hpa;
        }
        else{
            let pdpte_hpa = _eptPte(pdpte_gpa.pfn.bitwiseShiftLeft(12), eptp);
            if (pdpte_hpa === undefined) {
                println("Error [gvaTohpa] _eptPte(pdpte_gpa, eptp)");
                return;
            }

            // read pde entry - GPA
            // Pick and check PDEe.
            let pde_gpa = new PsEntry(readEntry(pdpte_hpa + 8 * i2));
            if (!pde_gpa.flags.present()) {
                println("PDe is not present");
                return;
            }

            // handle PDe Large page
            if (pde_gpa.flags.large) {
                let pfn = pde_gpa.value
                                .bitwiseAnd(MASK_MAXPHYADDR_52_BIT)
                                .bitwiseShiftRight(21)
                                .bitwiseAnd(host.parseInt64(1)
                                .bitwiseShiftLeft(PHYSICAL_ADDRESS_WIDTH_SUPPORTED - 21)
                                .subtract(1));
                let pa = pfn.bitwiseShiftLeft(21);
                let offset = va.bitwiseAnd(MASK_2MB_PAGE);
                let guest_gpa = pa.add(offset);
                let host_hpa = _eptPte(guest_gpa, eptp);
                println("GVA: " + hex(gva) + ", GPA: " + hex(guest_gpa) + ", HPA: " + hex(host_hpa));
                return host_hpa;
            }
            else{
                let pde_hpa = _eptPte(pde_gpa.pfn.bitwiseShiftLeft(12), eptp);
                if (pde_hpa === undefined) {
                    println("Error [gvaTohpa] _eptPte(pde_gpa, eptp)");
                    return;
                }

                // read pte entry - GPA
                // Pick and check PTe.
                let pte_gpa = new PsEntry(readEntry(pde_hpa + 8 * i1));
                if (!pte_gpa.flags.present()) {
                    println("PTe is not present");
                    return;
                }

                let pte_hpa = _eptPte(pte_gpa.pfn.bitwiseShiftLeft(12), eptp);
                if (pte_hpa === undefined) {
                    println("Error [gvaTohpa] _eptPte(pte_gpa, eptp)");
                    return;
                }

                let offset = gva.bitwiseAnd(MASK_12BIT);
                let guest_gpa = pte_hpa.add(offset);
                let host_hpa = _eptPte(guest_gpa, eptp);
                //println("pa: " + hex(pa));
                println("GVA: " + hex(gva) + ", GPA: " + hex(guest_gpa) + ", HPA: " + hex(host_hpa));
                return host_hpa;
            }
        }
    }

    function readEntry(address) {
        let line = exec("!dq " + hex(address) + " l1").Last();
        return host.parseInt64(line.replace(/`/g, "").substring(10).trim().split(" "), 16);
    }
}

// Returns fully-parsed EPT entries pointed by the current EPTP VMCS encoding.
function getCurrentEptPml4() {
    let exec_control1 = readVmcs(0x00004002);    // Primary processor-based VM-execution controls
    if (bits(exec_control1, 31, 1) == 0) {
        throw new Error("EPT is not enabled");
    }

    let exec_control2 = readVmcs(0x0000401E);    // Secondary processor-based VM-execution controls
    if (bits(exec_control2, 1, 1) == 0) {
        throw new Error("EPT is not enabled");
    }

    let eptp = readVmcs(0x0000201A);  // EPT pointer
    if (eptp === undefined) {
        throw new Error("The VMREAD instruction failed");
    }

    println("Current EPT pointer " + hex(eptp));
    return getEptPml4(eptp.bitwiseAnd(~0xfff));
}

// Returns the GUEST_CR3.
function getCurrentGuestCr3() {

    let guest_cr3 = readVmcs(0x6802);  // GUEST_CR3
    if (guest_cr3 === undefined) {
        throw new Error("The VMREAD instruction failed");
    }

    println("Current GUEST_CR3: " + hex(guest_cr3));
    return guest_cr3;
}

// Returns fully-parsed EPT entries rooted from the specified address.
function getEptPml4(pml4Addr) {
    // Cache fully parsed EPT if it is new, and return it.
    if (!g_eptCache[pml4Addr]) {
        g_eptCache[pml4Addr] = new EptPml4(pml4Addr);
    }
    return g_eptCache[pml4Addr];
}

// Reads a VMCS encoding. Returns 'undefined' if read fails.
function readVmcs(encoding) {
    // Capture the current state.
    // eg: efl=00000242 rax=0000000000006c1c rip=fffff813d4f00ea1
    let output = exec("r efl, rax, rip").Last();
    let originalRflags = output.substring(4, 12);
    let originalRax = output.substring(17, 33);
    let originalRip = output.substring(38, 54);

    let value = readVmcsUnsafe(encoding);

    // All done. Restore the original state.
    exec("r rax=" + originalRax + ", " +
        "rip=" + originalRip + ", " +
        "efl=" + originalRflags);

    return value;
}

// Reads a VMCS encoding without restoring register values.
function readVmcsUnsafe(encoding) {
    // Jump (back) to "VMREAD RAX, RAX", update RAX with encoding to read,
    // and execute the instruction.
    exec("r rip=" + hex(g_vmreadAddress) + ", rax=" + hex(encoding));
    if (exec("p").Last().includes("second chance")) {
        throw new Error("CPU exception occurred with the VMREAD instruction." +
            " Reboot the system with the .reboot command. This can happen" +
            " when the system in an early boot stage where the processor is" +
            " not in VMX operation.");
    }

    // Check whether the VMREAD instruction succeeded.
    // eg: efl=00000342 rax=0000000000000000
    let output = exec("r efl, rax").Last();
    let flags = host.parseInt64(output.substring(4, 12), 16);
    if ((flags & 0x41) == 0) {  // if CF==0 && ZF==0
        // Succeeded. RAX should contain the field value.
        return host.parseInt64(output.substring(17, 33), 16);
    } else {
        // VMREAD failed.
        return undefined;
    }
}

class EptPml4 {
    constructor(address) {
        this.address = address;
        this.entries = readPageAsTable(address, EptEntry, EptPdpt);
    }
}

class EptPdpt {
    constructor(address) {
        this.address = address;
        this.entries = readPageAsTable(address, EptEntry, EptPd);
    }
}

class EptPd {
    constructor(address) {
        this.address = address;
        this.entries = readPageAsTable(address, EptEntry, EptPt);
    }
}

class EptPt {
    constructor(address) {
        this.address = address;
        this.entries = readPageAsTable(address, EptEntry);
    }
}

// Represents a single EPT entry for any level of the tables.
class EptEntry {
    constructor(entry, nextTableType) {
        this.value = entry;
        this.flags = new EptFlags(entry);
        this.pfn = bits(entry, 12, 40);
        if (this.flags.present() && !this.flags.large && nextTableType !== undefined) {
            this.nextTable = new nextTableType(this.pfn.bitwiseShiftLeft(12));
        }
    }

    toString() {
        return hex(this.pfn) + " " + this.flags;
    }
}

// Partial representation of flags bits in any EPT entries. Only bits we care are
// represented.
// See: Figure 29-1. Formats of EPTP and EPT Paging-Structure Entries
class EptFlags {
    constructor(entry) {
        this.read = bits(entry, 0, 1);
        this.write = bits(entry, 1, 1);
        this.execute = bits(entry, 2, 1);
        this.memoryType = bits(entry, 3, 3);
        this.large = bits(entry, 7, 1);
        this.executeForUserMode = bits(entry, 10, 1);
        this.verifyGuestPaging = bits(entry, 57, 1);
        this.pagingWriteAccess = bits(entry, 58, 1);
        this.supervisorShadowStack = bits(entry, 60, 1);
    }

    toString() {
        return (
            { 1: "S", 0: "-" }[this.supervisorShadowStack] +
            { 1: "P", 0: "-" }[this.pagingWriteAccess] +
            { 1: "V", 0: "-" }[this.verifyGuestPaging] +
            { 1: "U", 0: "-" }[this.executeForUserMode] +
            { 1: "L", 0: "-" }[this.large] +
            this.memoryType +
            { 1: "X", 0: "-" }[this.execute] +
            { 1: "W", 0: "-" }[this.write] +
            { 1: "R", 0: "-" }[this.read]
        );
    }

    // Checks if translation is available. Note that the bit[10]
    // (executeForUserMode) is not consulted even if MBEC is enabled. (So, you
    // cannot create a user-mode-execute-only page.)
    present() {
        return (this.read || this.write || this.execute);
    }
}

class HlatPml4 {
    constructor(address) {
        this.address = address;
        this.entries = readPageAsTable(address, HlatEntry, HlatPdpt);
    }
}

class HlatPdpt {
    constructor(address) {
        this.address = address;
        if (!g_hlatCache[address]) {
            g_hlatCache[address] = readPageAsTable(address, HlatEntry, HlatPd);
        }
        this.entries = g_hlatCache[address];
    }
}

class HlatPd {
    constructor(address) {
        this.address = address;
        if (!g_hlatCache[address]) {
            g_hlatCache[address] = readPageAsTable(address, HlatEntry, HlatPt);
        }
        this.entries = g_hlatCache[address];
    }
}

class HlatPt {
    constructor(address) {
        this.address = address;
        if (!g_hlatCache[address]) {
            g_hlatCache[address] = readPageAsTable(address, HlatEntry);
        }
        this.entries = g_hlatCache[address];
    }
}

// Represents a single paging structure entry for any level of the tables.
class HlatEntry {
    constructor(entry, nextTableType) {
        this.value = entry;
        this.flags = new PsFlags(entry);
        this.pfn = bits(entry, 12, 40);
        if (this.flags.present() && !this.flags.large && !this.flags.restart && nextTableType !== undefined) {
            this.nextTable = new nextTableType(this.pfn.bitwiseShiftLeft(12));
        }
    }

    toString() {
        return hex(this.pfn) + " " + this.flags;
    }
}

// Represents a single paging structure entry for any level of the tables.
class PsEntry {
    constructor(entry) {
        this.value = entry;
        this.flags = new PsFlags(entry);
        this.pfn = bits(entry, 12, 40);
    }

    toString() {
        return hex(this.pfn) + " " + this.flags;
    }
}

// Partial representation of flags bits in any paging structure entries. Only
// bits we care are represented.
// See: Figure 4-11. Formats of CR3 and Paging-Structure Entries with 4-Level Paging and 5-Level Paging
class PsFlags {
    constructor(entry) {
        this.valid = bits(entry, 0, 1);
        this.write = bits(entry, 1, 1);
        this.user = bits(entry, 2, 1);
        this.accessed = bits(entry, 5, 1);
        this.dirty = bits(entry, 6, 1);
        this.large = bits(entry, 7, 1);
        this.restart = bits(entry, 11, 1);
        this.nonExecute = bits(entry, 63, 1);
    }

    toString() {
        if (!this.valid) {
            return "---------";
        }
        return (
            { 1: "L", 0: "-" }[this.large] +
            { 1: "D", 0: "-" }[this.dirty] +
            { 1: "A", 0: "-" }[this.accessed] +
            "--" +
            { 1: "U", 0: "K" }[this.user] +
            { 1: "W", 0: "R" }[this.write] +
            { 1: "-", 0: "E" }[this.nonExecute] +
            { 1: "V", 0: "-" }[this.valid]
        );
    }

    present() {
        return this.valid;
    }
}

// Reads a physical address for 4KB and constructs a table with 512 entries.
function readPageAsTable(address, entryType, nextTableType) {
    let entries = [];
    parseEach16Bytes(address.bitwiseAnd(~0xfff), 0x100, (l, h) =>
        entries.push(new entryType(l, nextTableType), new entryType(h, nextTableType)));
    return entries;
}

// Takes specified range of bits from the 64bit value.
function bits(value, offset, size) {
    let mask = host.Int64(1).bitwiseShiftLeft(size).subtract(1);
    return value.bitwiseShiftRight(offset).bitwiseAnd(mask).asNumber();
}

// Parses 16 bytes at the given physical address into two 8 byte integers.
function parseEach16Bytes(physicalAddress, count, callback) {
    for (let line of exec("!dq " + hex(physicalAddress) + " l" + hex(count * 2))) {
        let values = line.replace(/`/g, "").substring(10).trim().split(" ");
        try {
            var low = host.parseInt64(values[0], 16);
            var high = host.parseInt64(values[1], 16);
        } catch (error) {
            throw new Error("Failed to parse: " + line);
        }
        callback(low, high);
    }
}

const print = msg => host.diagnostics.debugLog(msg);
const println = msg => print(msg + "\n");
const hex = (num, padding = 0) => "0x" + num.toString(16).padStart(padding, "0");
const exec = cmd => host.namespace.Debugger.Utility.Control.ExecuteCommand(cmd);

// The list of VMCS encodings as of the revision 83, March 2024.
const VMCS_ENCODINGS = [
    "VPID", 0x0000,
    "POSTED_INTERRUPT_NOTIFICATION_VECTOR", 0x0002,
    "EPTP_INDEX", 0x0004,
    "HLAT_PREFIX_SIZE", 0x0006,
    "LAST_PID_POINTER_INDEX", 0x0008,
    "GUEST_ES_SELECTOR", 0x0800,
    "GUEST_CS_SELECTOR", 0x0802,
    "GUEST_SS_SELECTOR", 0x0804,
    "GUEST_DS_SELECTOR", 0x0806,
    "GUEST_FS_SELECTOR", 0x0808,
    "GUEST_GS_SELECTOR", 0x080A,
    "GUEST_LDTR_SELECTOR", 0x080C,
    "GUEST_TR_SELECTOR", 0x080E,
    "GUEST_INTERRUPT_STATUS", 0x0810,
    "GUEST_PML_INDEX", 0x0812,
    "GUEST_UINV3", 0x0814,
    "HOST_ES_SELECTOR", 0x0C00,
    "HOST_CS_SELECTOR", 0x0C02,
    "HOST_SS_SELECTOR", 0x0C04,
    "HOST_DS_SELECTOR", 0x0C06,
    "HOST_FS_SELECTOR", 0x0C08,
    "HOST_GS_SELECTOR", 0x0C0A,
    "HOST_TR_SELECTOR", 0x0C0C,
    "ADDRESS_OF_IO_BITMAP_A", 0x2000,
    "ADDRESS_OF_IO_BITMAP_B", 0x2002,
    "ADDRESS_OF_MSR_BITMAPS", 0x2004,
    "VM_EXIT_MSR_STORE_ADDR", 0x2006,
    "VM_EXIT_MSR_LOAD_ADDR", 0x2008,
    "VM_ENTRY_MSR_LOAD_ADDR", 0x200A,
    "EXECUTIVE_VMCS_PTR", 0x200C,
    "PML_ADDR", 0x200E,
    "TSC_OFFSET", 0x2010,
    "VIRTUAL_APIC_PAGE_ADDR", 0x2012,
    "APIC_ACCESS_ADDR", 0x2014,
    "PI_DESC_ADDR", 0x2016,
    "VM_FUNCTION_CONTROL", 0x2018,
    "EPT_POINTER", 0x201A,
    "EOI_EXIT_BITMAP_0", 0x201C,
    "EOI_EXIT_BITMAP_1", 0x201E,
    "EOI_EXIT_BITMAP_2", 0x2020,
    "EOI_EXIT_BITMAP_3", 0x2022,
    "EPTP_LIST_ADDRESS", 0x2024,
    "VMREAD_BITMAP_ADDRESS", 0x2026,
    "VMWRITE_BITMAP_ADDRESS", 0x2028,
    "VIRTUALIZATION_EXCEPTION_INFORMATION_ADDRESS", 0x202A,
    "XSS_EXIT_BITMAP", 0x202C,
    "ENCLS_EXITING_BITMAP", 0x202E,
    "SUB_PAGE_PERMISSION_TABLE_POINTER", 0x2030,
    "TSC_MULTIPLIER", 0x2032,
    "TERTIARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS", 0x2034,
    "ENCLV_EXITING_BITMAP", 0x2036,
    "LOW_PASID_DIRECTORY_ADDRESS", 0x2038,
    "HIGH_PASID_DIRECTORY_ADDRESS", 0x203A,
    "SHARED_EPT_POINTER", 0x203C,
    "PCONFIG_EXITING_BITMAP", 0x203E,
    "HYPERVISOR_MANAGED_LINEAR_ADDRESS_TRANSLATION_POINTER", 0x2040,
    "PID_POINTER_TABLE_ADDRESS", 0x2042,
    "SECONDARY_VM_EXIT_CONTROLS", 0x2044,
    "GUEST_PHYSICAL_ADDRESS", 0x2400,
    "VMCS_LINK_POINTER", 0x2800,
    "GUEST_IA32_DEBUGCTL", 0x2802,
    "GUEST_IA32_PAT", 0x2804,
    "GUEST_IA32_EFER", 0x2806,
    "GUEST_IA32_PERF_GLOBAL_CTRL", 0x2808,
    "GUEST_PDPTE0", 0x280A,
    "GUEST_PDPTE1", 0x280C,
    "GUEST_PDPTE2", 0x280E,
    "GUEST_PDPTE3", 0x2810,
    "GUEST_IA32_BNDCFGS", 0x2812,
    "GUEST_IA32_RTIT_CTL", 0x2814,
    "GUEST_IA32_LBR_CTL", 0x2816,
    "GUEST_IA32_PKRS", 0x2818,
    "HOST_IA32_PAT", 0x2C00,
    "HOST_IA32_EFER", 0x2C02,
    "HOST_IA32_PERF_GLOBAL_CTRL", 0x2C04,
    "HOST_IA32_PKRS", 0x2C06,
    "PIN_BASED_VM_EXEC_CONTROL", 0x4000,
    "PRIMARY_PROCESSOR_BASED_VM_EXEC_CONTROL", 0x4002,
    "EXCEPTION_BITMAP", 0x4004,
    "PAGE_FAULT_ERROR_CODE_MASK", 0x4006,
    "PAGE_FAULT_ERROR_CODE_MATCH", 0x4008,
    "CR3_TARGET_COUNT", 0x400A,
    "PRIMARY_VM_EXIT_CONTROLS", 0x400C,
    "VM_EXIT_MSR_STORE_COUNT", 0x400E,
    "VM_EXIT_MSR_LOAD_COUNT", 0x4010,
    "VM_ENTRY_CONTROLS", 0x4012,
    "VM_ENTRY_MSR_LOAD_COUNT", 0x4014,
    "VM_ENTRY_INTR_INFO_FIELD", 0x4016,
    "VM_ENTRY_EXCEPTION_ERROR_CODE", 0x4018,
    "VM_ENTRY_INSTRUCTION_LEN", 0x401A,
    "TPR_THRESHOLD", 0x401C,
    "SECONDARY_PROCESSOR_BASED_VM_EXEC_CONTROL", 0x401E,
    "PLE_GAP", 0x4020,
    "PLE_WINDOW", 0x4022,
    "VM_INSTRUCTION_ERROR", 0x4400,
    "EXIT_REASON", 0x4402,
    "VM_EXIT_INTERRUPTION_INFORMATION", 0x4404,
    "VM_EXIT_INTERRUPTION_ERROR_CODE", 0x4406,
    "IDT_VECTORING_INFORMATION", 0x4408,
    "IDT_VECTORING_ERROR_CODE", 0x440A,
    "VM_EXIT_INSTRUCTION_LENGTH", 0x440C,
    "VM_EXIT_INSTRUCTION_INFO", 0x440E,
    "GUEST_ES_LIMIT", 0x4800,
    "GUEST_CS_LIMIT", 0x4802,
    "GUEST_SS_LIMIT", 0x4804,
    "GUEST_DS_LIMIT", 0x4806,
    "GUEST_FS_LIMIT", 0x4808,
    "GUEST_GS_LIMIT", 0x480A,
    "GUEST_LDTR_LIMIT", 0x480C,
    "GUEST_TR_LIMIT", 0x480E,
    "GUEST_GDTR_LIMIT", 0x4810,
    "GUEST_IDTR_LIMIT", 0x4812,
    "GUEST_ES_ACCESS_RIGHTS", 0x4814,
    "GUEST_CS_ACCESS_RIGHTS", 0x4816,
    "GUEST_SS_ACCESS_RIGHTS", 0x4818,
    "GUEST_DS_ACCESS_RIGHTS", 0x481A,
    "GUEST_FS_ACCESS_RIGHTS", 0x481C,
    "GUEST_GS_ACCESS_RIGHTS", 0x481E,
    "GUEST_LDTR_ACCESS_RIGHTS", 0x4820,
    "GUEST_TR_ACCESS_RIGHTS", 0x4822,
    "GUEST_INTERRUPTIBILITY_STATE", 0x4824,
    "GUEST_ACTIVITY_STATE", 0x4826,
    "GUEST_SMBASE", 0x4828,
    "GUEST_SYSENTER_CS", 0x482A,
    "VMX_PREEMPTION_TIMER_VALUE", 0x482E,
    "HOST_IA32_SYSENTER_CS", 0x4C00,
    "CR0_GUEST_HOST_MASK", 0x6000,
    "CR4_GUEST_HOST_MASK", 0x6002,
    "CR0_READ_SHADOW", 0x6004,
    "CR4_READ_SHADOW", 0x6006,
    "CR3_TARGET_VALUE0", 0x6008,
    "CR3_TARGET_VALUE1", 0x600A,
    "CR3_TARGET_VALUE2", 0x600C,
    "CR3_TARGET_VALUE3", 0x600E,
    "EXIT_QUALIFICATION", 0x6400,
    "IO_RCX", 0x6402,
    "IO_RSI", 0x6404,
    "IO_RDI", 0x6406,
    "IO_RIP", 0x6408,
    "GUEST_LINEAR_ADDRESS", 0x640A,
    "GUEST_CR0", 0x6800,
    "GUEST_CR3", 0x6802,
    "GUEST_CR4", 0x6804,
    "GUEST_ES_BASE", 0x6806,
    "GUEST_CS_BASE", 0x6808,
    "GUEST_SS_BASE", 0x680A,
    "GUEST_DS_BASE", 0x680C,
    "GUEST_FS_BASE", 0x680E,
    "GUEST_GS_BASE", 0x6810,
    "GUEST_LDTR_BASE", 0x6812,
    "GUEST_TR_BASE", 0x6814,
    "GUEST_GDTR_BASE", 0x6816,
    "GUEST_IDTR_BASE", 0x6818,
    "GUEST_DR7", 0x681A,
    "GUEST_RSP", 0x681C,
    "GUEST_RIP", 0x681E,
    "GUEST_RFLAGS", 0x6820,
    "GUEST_PENDING_DBG_EXCEPTIONS", 0x6822,
    "GUEST_SYSENTER_ESP", 0x6824,
    "GUEST_SYSENTER_EIP", 0x6826,
    "GUEST_IA32_S_CET1", 0x6828,
    "GUEST_SSP", 0x682A,
    "GUEST_IA32_INTERRUPT_SSP_TABLE_ADDR", 0x682C,
    "HOST_CR0", 0x6C00,
    "HOST_CR3", 0x6C02,
    "HOST_CR4", 0x6C04,
    "HOST_FS_BASE", 0x6C06,
    "HOST_GS_BASE", 0x6C08,
    "HOST_TR_BASE", 0x6C0A,
    "HOST_GDTR_BASE", 0x6C0C,
    "HOST_IDTR_BASE", 0x6C0E,
    "HOST_IA32_SYSENTER_ESP", 0x6C10,
    "HOST_IA32_SYSENTER_EIP", 0x6C12,
    "HOST_RSP", 0x6C14,
    "HOST_RIP", 0x6C16,
    "HOST_IA32_S_CET1", 0x6C18,
    "HOST_SSP", 0x6C1A,
    "HOST_IA32_INTERRUPT_SSP_TABLE_ADDR", 0x6C1C
];
