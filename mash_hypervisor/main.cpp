#include <intrin.h>
#include <ntifs.h>
#include <ntimage.h>
#include <windef.h>
#define page_shift 12L
#define DebugPrint(...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, __VA_ARGS__)
namespace cpu {
typedef union {
    uintptr_t AsUInt64;
    struct {
        uintptr_t Reserved1 : 3;
        uintptr_t WriteThrough : 1;
        uintptr_t CacheDisable : 1;
        uintptr_t Reserved2 : 7;
        uintptr_t PageFrameNumber : 36;
        uintptr_t Reserved3 : 16;
    } field;
} _cr3;
struct _cpuid {
    unsigned int rax;
    unsigned int rbx;
    unsigned int rcx;
    unsigned int rdx;
};
};  // namespace cpu

// copy from hyperduck tools.cpp
namespace tools {
auto virtual_to_physical(uintptr_t virtualaddress) -> uintptr_t {
    PHYSICAL_ADDRESS pa;
    pa = MmGetPhysicalAddress(reinterpret_cast<void*>(virtualaddress));
    return pa.QuadPart;
}
auto get_phyaddress_by_pfn(uintptr_t pfn) -> uintptr_t {
    return static_cast<uintptr_t>(pfn) << page_shift;
}
auto physical_to_virtual(uintptr_t pa) -> uintptr_t {
    PHYSICAL_ADDRESS phy_address_transform;
    phy_address_transform.QuadPart = pa;
    return reinterpret_cast<uintptr_t>(
        MmGetVirtualForPhysical(phy_address_transform));
}
auto allocate_contiguous_memory(unsigned long size) -> void* {
    PHYSICAL_ADDRESS phys = {0};
    phys.QuadPart = ~0ULL;
    PVOID result = MmAllocateContiguousMemory(size, phys);
    if (result) RtlSecureZeroMemory(result, size);
    return result;
}
auto free_contiguous_memory(void* address) -> void {
    MmFreeContiguousMemory(address);
};
auto get_cpu_num() -> size_t {
    return static_cast<size_t>(__readgsbyte(0x184));
}
}  // namespace tools
auto drv_entry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path)
    -> NTSTATUS {
    UNREFERENCED_PARAMETER(driver_object);
    UNREFERENCED_PARAMETER(registry_path);
    PAGED_CODE();
    cpu::_cpuid cpuid_info = {0};
    static const auto pml4_table_size = sizeof(void*) * 512;
    cpu::_cr3 system_cr3_value;
    system_cr3_value.AsUInt64 = __readcr3();
    cpu::_cr3 build_cr3_value;
    build_cr3_value.AsUInt64 = __readcr3();
    // copy the system cr3 for backup
    const auto kernel_pml4_pa =
        tools::get_phyaddress_by_pfn(system_cr3_value.field.PageFrameNumber);
    const auto kernel_pml4_va =
        reinterpret_cast<void*>(tools::physical_to_virtual(kernel_pml4_pa));
    void* pml4_backup_va = tools::allocate_contiguous_memory(pml4_table_size);
    NT_ASSERT(pml4_backup_va);
    // build own cr3 value
    memcpy(pml4_backup_va, kernel_pml4_va, pml4_table_size);
    build_cr3_value.field.PageFrameNumber =
        (tools::virtual_to_physical(
             reinterpret_cast<uintptr_t>(pml4_backup_va)) >>
         page_shift);

    KIRQL irql;
    KeRaiseIrql(DISPATCH_LEVEL, &irql);

    __writecr3(build_cr3_value.AsUInt64);
    _mm_lfence();
    // mash host cr3 memeory
    memset(kernel_pml4_va, 0x0, pml4_table_size);
    __rdtsc();
    _mm_lfence();
    __readmsr(0xc0000082);
    auto mash_cr3 = __readcr3();
    _mm_lfence();
    // restore cr3
    memcpy(kernel_pml4_va, pml4_backup_va, pml4_table_size);
    __writecr3(system_cr3_value.AsUInt64);
    _mm_lfence();

    KeLowerIrql(irql);
    DebugPrint("mash cr3: %p build cr3: %p org cr3: %p \n", mash_cr3,
               build_cr3_value.AsUInt64, system_cr3_value.AsUInt64);
    tools::free_contiguous_memory(pml4_backup_va);
    // for lazy duck
    return STATUS_UNSUCCESSFUL;
}
extern "C" NTSTATUS NTAPI DriverEntry(__in PDRIVER_OBJECT DriverObject,
                                      __in PUNICODE_STRING RegistryPath) {
    return drv_entry(DriverObject, RegistryPath);
};
