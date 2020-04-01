#include <CommonCrypto/CommonCrypto.h>
#include <CoreFoundation/CoreFoundation.h>
#include <mach-o/loader.h>
#include <mach/mach.h>

#define PROC_TASK_OFF (0x10)
#define OS_STRING_STRING_OFF (0x10)
#define OS_DICTIONARY_COUNT_OFF (0x14)
#define IO_DT_NVRAM_OF_DICT_OFF (0xC0)
#define IPC_PORT_IP_KOBJECT_OFF (0x68)
#define OS_DICTIONARY_DICT_ENTRY_OFF (0x20)
#ifdef __arm64e__
#	define CPU_DATA_RTCLOCK_DATAP_OFF (0x190)
#else
#	define CPU_DATA_RTCLOCK_DATAP_OFF (0x198)
#endif
#define VM_KERNEL_LINK_ADDRESS (0xFFFFFFF007004000ULL)
#define APPLE_MOBILE_AP_NONCE_GENERATE_NONCE_SEL (0xC8)
#define kCFCoreFoundationVersionNumber_iOS_13_0_b2 (1656)
#define kCFCoreFoundationVersionNumber_iOS_13_0_b1 (1652.20)
#define APPLE_MOBILE_AP_NONCE_BOOT_NONCE_OS_SYMBOL_OFF (0xC0)
#define PROC_P_PID_OFF (kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_13_0_b2 ? 0x68 : 0x60)
#define TASK_ITK_REGISTERED_OFF (kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_13_0_b1 ? 0x308 : 0x2E8)

#define KADDR_FMT "0x%" PRIX64
#define VM_KERN_MEMORY_CPU (9)
#define RD(a) extract32(a, 0, 5)
#define RN(a) extract32(a, 5, 5)
#define IS_RET(a) ((a) == 0xD65F03C0U)
#define ADRP_ADDR(a) ((a) & ~0xFFFULL)
#define ADRP_IMM(a) (ADR_IMM(a) << 12U)
#define IO_OBJECT_NULL ((io_object_t)0)
#define ADD_X_IMM(a) extract32(a, 10, 12)
#define LDR_X_IMM(a) (sextract64(a, 5, 19) << 2U)
#define IS_ADR(a) (((a) & 0x9F000000U) == 0x10000000U)
#define IS_ADRP(a) (((a) & 0x9F000000U) == 0x90000000U)
#define IS_ADD_X(a) (((a) & 0xFFC00000U) == 0x91000000U)
#define IS_LDR_X(a) (((a) & 0xFF000000U) == 0x58000000U)
#define LDR_X_UNSIGNED_IMM(a) (extract32(a, 10, 12) << 3U)
#define kBootNoncePropertyKey "com.apple.System.boot-nonce"
#define kIONVRAMDeletePropertyKey "IONVRAM-DELETE-PROPERTY"
#define IS_LDR_X_UNSIGNED_IMM(a) (((a) & 0xFFC00000U) == 0xF9400000U)
#define ADR_IMM(a) ((sextract64(a, 5, 19) << 2U) | extract32(a, 29, 2))
#define kIONVRAMForceSyncNowPropertyKey "IONVRAM-FORCESYNCNOW-PROPERTY"

#ifndef SEG_TEXT_EXEC
#	define SEG_TEXT_EXEC "__TEXT_EXEC"
#endif

#ifndef SECT_CSTRING
#	define SECT_CSTRING "__cstring"
#endif

#ifndef MIN
#	define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

typedef uint64_t kaddr_t;
typedef mach_port_t io_object_t;
typedef io_object_t io_service_t;
typedef io_object_t io_connect_t;
typedef io_object_t io_registry_entry_t;

typedef struct {
	struct section_64 s64;
	char *data;
} sec_64_t;

typedef struct {
	sec_64_t sec_text, sec_cstring;
} pfinder_t;

typedef struct {
	kaddr_t key, val;
} dict_entry_t;

kern_return_t
IOServiceClose(io_connect_t);

kern_return_t
IOObjectRelease(io_object_t);

CFMutableDictionaryRef
IOServiceMatching(const char *);

io_service_t
IOServiceGetMatchingService(mach_port_t, CFDictionaryRef);

kern_return_t
IOServiceOpen(io_service_t, task_port_t, uint32_t, io_connect_t *);

kern_return_t
IORegistryEntrySetCFProperty(io_registry_entry_t, CFStringRef, CFTypeRef);

kern_return_t
mach_vm_write(vm_map_t, mach_vm_address_t, vm_offset_t, mach_msg_type_number_t);

kern_return_t
IOConnectCallStructMethod(io_connect_t, uint32_t, const void *, size_t, void *, size_t *);

kern_return_t
mach_vm_read_overwrite(vm_map_t, mach_vm_address_t, mach_vm_size_t, mach_vm_address_t, mach_vm_size_t *);

kern_return_t
mach_vm_machine_attribute(vm_map_t, mach_vm_address_t, mach_vm_size_t, vm_machine_attribute_t, vm_machine_attribute_val_t *);

kern_return_t
mach_vm_region(vm_map_t, mach_vm_address_t *, mach_vm_size_t *, vm_region_flavor_t, vm_region_info_t, mach_msg_type_number_t *, mach_port_t *);

extern const mach_port_t kIOMasterPortDefault;

static kaddr_t allproc, our_task;
static task_t tfp0 = MACH_PORT_NULL;

static uint32_t
extract32(uint32_t val, unsigned start, unsigned len) {
	return (val >> start) & (~0U >> (32U - len));
}

static uint64_t
sextract64(uint64_t val, unsigned start, unsigned len) {
	return (uint64_t)((int64_t)(val << (64U - len - start)) >> (64U - len));
}

static kern_return_t
init_tfp0(void) {
	kern_return_t ret = task_for_pid(mach_task_self(), 0, &tfp0);
	mach_port_t host;
	pid_t pid;

	if(ret != KERN_SUCCESS) {
		host = mach_host_self();
		if(MACH_PORT_VALID(host)) {
			printf("host: 0x%" PRIX32 "\n", host);
			ret = host_get_special_port(host, HOST_LOCAL_NODE, 4, &tfp0);
			mach_port_deallocate(mach_task_self(), host);
		}
	}
	if(ret == KERN_SUCCESS && MACH_PORT_VALID(tfp0)) {
		if(pid_for_task(tfp0, &pid) == KERN_SUCCESS && pid == 0) {
			return ret;
		}
		mach_port_deallocate(mach_task_self(), tfp0);
	}
	return KERN_FAILURE;
}

static kern_return_t
kread_buf(kaddr_t addr, void *buf, mach_vm_size_t sz) {
	mach_vm_address_t p = (mach_vm_address_t)buf;
	mach_vm_size_t read_sz, out_sz = 0;

	while(sz != 0) {
		read_sz = MIN(sz, vm_kernel_page_size - (addr & vm_kernel_page_mask));
		if(mach_vm_read_overwrite(tfp0, addr, read_sz, p, &out_sz) != KERN_SUCCESS || out_sz != read_sz) {
			return KERN_FAILURE;
		}
		p += read_sz;
		sz -= read_sz;
		addr += read_sz;
	}
	return KERN_SUCCESS;
}

static void *
kread_buf_alloc(kaddr_t addr, mach_vm_size_t read_sz) {
	void *buf = malloc(read_sz);

	if(buf != NULL) {
		if(kread_buf(addr, buf, read_sz) == KERN_SUCCESS) {
			return buf;
		}
		free(buf);
	}
	return NULL;
}

static kern_return_t
kread_addr(kaddr_t addr, kaddr_t *val) {
	return kread_buf(addr, val, sizeof(*val));
}

static kern_return_t
kwrite_buf(kaddr_t addr, const void *buf, mach_msg_type_number_t sz) {
	vm_machine_attribute_val_t mattr_val = MATTR_VAL_CACHE_FLUSH;
	mach_vm_address_t p = (mach_vm_address_t)buf;
	mach_msg_type_number_t write_sz;

	while(sz != 0) {
		write_sz = (mach_msg_type_number_t)MIN(sz, vm_kernel_page_size - (addr & vm_kernel_page_mask));
		if(mach_vm_write(tfp0, addr, p, write_sz) != KERN_SUCCESS || mach_vm_machine_attribute(tfp0, addr, write_sz, MATTR_CACHE, &mattr_val) != KERN_SUCCESS) {
			return KERN_FAILURE;
		}
		p += write_sz;
		sz -= write_sz;
		addr += write_sz;
	}
	return KERN_SUCCESS;
}

static kaddr_t
get_kbase(kaddr_t *kslide) {
	mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
	vm_region_extended_info_data_t extended_info;
	task_dyld_info_data_t dyld_info;
	kaddr_t addr, rtclock_datap;
	struct mach_header_64 mh64;
	mach_port_t obj_nm;
	mach_vm_size_t sz;

	if(task_info(tfp0, TASK_DYLD_INFO, (task_info_t)&dyld_info, &cnt) == KERN_SUCCESS && dyld_info.all_image_info_size != 0) {
		*kslide = dyld_info.all_image_info_size;
		return VM_KERNEL_LINK_ADDRESS + *kslide;
	}
	cnt = VM_REGION_EXTENDED_INFO_COUNT;
	for(addr = 0; mach_vm_region(tfp0, &addr, &sz, VM_REGION_EXTENDED_INFO, (vm_region_info_t)&extended_info, &cnt, &obj_nm) == KERN_SUCCESS; addr += sz) {
		mach_port_deallocate(mach_task_self(), obj_nm);
		if(extended_info.user_tag == VM_KERN_MEMORY_CPU && extended_info.protection == VM_PROT_DEFAULT) {
			if(kread_addr(addr + CPU_DATA_RTCLOCK_DATAP_OFF, &rtclock_datap) != KERN_SUCCESS) {
				break;
			}
			printf("rtclock_datap: " KADDR_FMT "\n", rtclock_datap);
			rtclock_datap = trunc_page_kernel(rtclock_datap);
			do {
				if(rtclock_datap <= VM_KERNEL_LINK_ADDRESS) {
					return 0;
				}
				rtclock_datap -= vm_kernel_page_size;
				if(kread_buf(rtclock_datap, &mh64, sizeof(mh64)) != KERN_SUCCESS) {
					return 0;
				}
			} while(mh64.magic != MH_MAGIC_64 || mh64.cputype != CPU_TYPE_ARM64 || mh64.filetype != MH_EXECUTE);
			*kslide = rtclock_datap - VM_KERNEL_LINK_ADDRESS;
			return rtclock_datap;
		}
	}
	return 0;
}

static kern_return_t
find_section(kaddr_t sg64_addr, struct segment_command_64 sg64, const char *sect_name, struct section_64 *sp) {
	kaddr_t s64_addr, s64_end;

	for(s64_addr = sg64_addr + sizeof(sg64), s64_end = s64_addr + (sg64.cmdsize - sizeof(*sp)); s64_addr < s64_end; s64_addr += sizeof(*sp)) {
		if(kread_buf(s64_addr, sp, sizeof(*sp)) != KERN_SUCCESS) {
			break;
		}
		if(strncmp(sp->segname, sg64.segname, sizeof(sp->segname)) == 0 && strncmp(sp->sectname, sect_name, sizeof(sp->sectname)) == 0) {
			return KERN_SUCCESS;
		}
	}
	return KERN_FAILURE;
}

static void
sec_reset(sec_64_t *sec) {
	memset(&sec->s64, '\0', sizeof(sec->s64));
	sec->data = NULL;
}

static void
sec_term(sec_64_t *sec) {
	free(sec->data);
	sec_reset(sec);
}

static kern_return_t
sec_init(sec_64_t *sec) {
	if((sec->data = malloc(sec->s64.size)) != NULL) {
		if(kread_buf(sec->s64.addr, sec->data, sec->s64.size) == KERN_SUCCESS) {
			return KERN_SUCCESS;
		}
		sec_term(sec);
	}
	return KERN_FAILURE;
}

static void
pfinder_reset(pfinder_t *pfinder) {
	sec_reset(&pfinder->sec_text);
	sec_reset(&pfinder->sec_cstring);
}

static void
pfinder_term(pfinder_t *pfinder) {
	sec_term(&pfinder->sec_text);
	sec_term(&pfinder->sec_cstring);
	pfinder_reset(pfinder);
}

static kern_return_t
pfinder_init(pfinder_t *pfinder, kaddr_t kbase) {
	kern_return_t ret = KERN_FAILURE;
	struct segment_command_64 sg64;
	kaddr_t sg64_addr, sg64_end;
	struct mach_header_64 mh64;
	struct section_64 s64;

	pfinder_reset(pfinder);
	if(kread_buf(kbase, &mh64, sizeof(mh64)) == KERN_SUCCESS && mh64.magic == MH_MAGIC_64 && mh64.cputype == CPU_TYPE_ARM64 && mh64.filetype == MH_EXECUTE) {
		for(sg64_addr = kbase + sizeof(mh64), sg64_end = sg64_addr + (mh64.sizeofcmds - sizeof(sg64)); sg64_addr < sg64_end; sg64_addr += sg64.cmdsize) {
			if(kread_buf(sg64_addr, &sg64, sizeof(sg64)) != KERN_SUCCESS) {
				break;
			}
			if(sg64.cmd == LC_SEGMENT_64) {
				if(strncmp(sg64.segname, SEG_TEXT_EXEC, sizeof(sg64.segname)) == 0 && find_section(sg64_addr, sg64, SECT_TEXT, &s64) == KERN_SUCCESS) {
					pfinder->sec_text.s64 = s64;
					printf("sec_text_addr: " KADDR_FMT ", sec_text_sz: 0x%" PRIX64 "\n", s64.addr, s64.size);
				} else if(strncmp(sg64.segname, SEG_TEXT, sizeof(sg64.segname)) == 0 && find_section(sg64_addr, sg64, SECT_CSTRING, &s64) == KERN_SUCCESS) {
					pfinder->sec_cstring.s64 = s64;
					printf("sec_cstring_addr: " KADDR_FMT ", sec_cstring_sz: 0x%" PRIX64 "\n", s64.addr, s64.size);
				}
			}
			if(pfinder->sec_text.s64.size != 0 && pfinder->sec_cstring.s64.size != 0) {
				if(sec_init(&pfinder->sec_text) == KERN_SUCCESS) {
					ret = sec_init(&pfinder->sec_cstring);
				}
				break;
			}
		}
	}
	if(ret != KERN_SUCCESS) {
		pfinder_term(pfinder);
	}
	return ret;
}

static kaddr_t
pfinder_xref_rd(pfinder_t pfinder, uint32_t rd, kaddr_t start, kaddr_t to) {
	uint64_t x[32] = { 0 };
	uint32_t insn;

	for(; start >= pfinder.sec_text.s64.addr && start < pfinder.sec_text.s64.addr + (pfinder.sec_text.s64.size - sizeof(insn)); start += sizeof(insn)) {
		memcpy(&insn, pfinder.sec_text.data + (start - pfinder.sec_text.s64.addr), sizeof(insn));
		if(IS_LDR_X(insn)) {
			x[RD(insn)] = start + LDR_X_IMM(insn);
		} else if(IS_ADR(insn)) {
			x[RD(insn)] = start + ADR_IMM(insn);
		} else if(IS_ADRP(insn)) {
			x[RD(insn)] = ADRP_ADDR(start) + ADRP_IMM(insn);
			continue;
		} else if(IS_ADD_X(insn)) {
			x[RD(insn)] = x[RN(insn)] + ADD_X_IMM(insn);
		} else if(IS_LDR_X_UNSIGNED_IMM(insn)) {
			x[RD(insn)] = x[RN(insn)] + LDR_X_UNSIGNED_IMM(insn);
		} else if(IS_RET(insn)) {
			memset(x, '\0', sizeof(x));
		}
		if(RD(insn) == rd) {
			if(to == 0) {
				return x[rd];
			}
			if(x[rd] == to) {
				return start;
			}
		}
	}
	return 0;
}

static kaddr_t
pfinder_xref_str(pfinder_t pfinder, const char *str, uint32_t rd) {
	const char *p, *e;
	size_t len;

	for(p = pfinder.sec_cstring.data, e = p + pfinder.sec_cstring.s64.size; p < e; p += len) {
		len = strlen(p) + 1;
		if(strncmp(str, p, len) == 0) {
			return pfinder_xref_rd(pfinder, rd, pfinder.sec_text.s64.addr, pfinder.sec_cstring.s64.addr + (kaddr_t)(p - pfinder.sec_cstring.data));
		}
	}
	return 0;
}

static kaddr_t
pfinder_allproc(pfinder_t pfinder) {
	kaddr_t ref = pfinder_xref_str(pfinder, "shutdownwait", 2);

	if(ref == 0) {
		ref = pfinder_xref_str(pfinder, "shutdownwait", 3); /* msleep */
	}
	return pfinder_xref_rd(pfinder, 8, ref, 0);
}

static kern_return_t
pfinder_init_offsets(pfinder_t pfinder) {
	if((allproc = pfinder_allproc(pfinder)) != 0) {
		printf("allproc: " KADDR_FMT "\n", allproc);
		return KERN_SUCCESS;
	}
	return KERN_FAILURE;
}

static kern_return_t
find_task(pid_t pid, kaddr_t *task) {
	kaddr_t proc = allproc;
	pid_t cur_pid;

	while(kread_addr(proc, &proc) == KERN_SUCCESS && proc != 0) {
		if(kread_buf(proc + PROC_P_PID_OFF, &cur_pid, sizeof(cur_pid)) == KERN_SUCCESS && cur_pid == pid) {
			return kread_addr(proc + PROC_TASK_OFF, task);
		}
	}
	return KERN_FAILURE;
}

static io_service_t
get_serv(const char *name) {
	return IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching(name));
}

static kaddr_t
get_port(mach_port_t port) {
	kaddr_t ipc_port = 0;

	if(mach_ports_register(mach_task_self(), &port, 1) == KERN_SUCCESS) {
		if(kread_addr(our_task + TASK_ITK_REGISTERED_OFF, &ipc_port) != KERN_SUCCESS) {
			ipc_port = 0;
		}
		mach_ports_register(mach_task_self(), NULL, 0);
	}
	return ipc_port;
}

static kern_return_t
get_object(io_service_t serv, kaddr_t *object) {
	kaddr_t ipc_port;

	if((ipc_port = get_port(serv)) != 0) {
		printf("ipc_port: " KADDR_FMT "\n", ipc_port);
		return kread_addr(ipc_port + IPC_PORT_IP_KOBJECT_OFF, object);
	}
	return KERN_FAILURE;
}

static kern_return_t
nonce_generate(io_service_t nonce_serv) {
	uint8_t nonce_d[CC_SHA384_DIGEST_LENGTH];
	size_t nonce_d_sz = sizeof(nonce_d);
	kern_return_t ret = KERN_FAILURE;
	io_connect_t nonce_conn;

	if(IOServiceOpen(nonce_serv, mach_task_self(), 0, &nonce_conn) == KERN_SUCCESS) {
		printf("nonce_conn: 0x%" PRIX32 "\n", nonce_conn);
		ret = IOConnectCallStructMethod(nonce_conn, APPLE_MOBILE_AP_NONCE_GENERATE_NONCE_SEL, NULL, 0, nonce_d, &nonce_d_sz);
		IOServiceClose(nonce_conn);
	}
	return ret;
}

static kern_return_t
get_boot_nonce_os_symbol(io_service_t nonce_serv, kaddr_t *boot_nonce_os_symbol) {
	kaddr_t nonce_object;

	if(get_object(nonce_serv, &nonce_object) == KERN_SUCCESS) {
		printf("nonce_object: " KADDR_FMT "\n", nonce_object);
		return kread_addr(nonce_object + APPLE_MOBILE_AP_NONCE_BOOT_NONCE_OS_SYMBOL_OFF, boot_nonce_os_symbol);
	}
	return KERN_FAILURE;
}

static kern_return_t
get_of_dict(io_service_t nvram_serv, kaddr_t *of_dict) {
	kaddr_t nvram_object;

	if(get_object(nvram_serv, &nvram_object) == KERN_SUCCESS) {
		printf("nvram_object: " KADDR_FMT "\n", nvram_object);
		return kread_addr(nvram_object + IO_DT_NVRAM_OF_DICT_OFF, of_dict);
	}
	return KERN_FAILURE;
}

static kaddr_t
lookup_key_in_os_dict(kaddr_t os_dict, kaddr_t key) {
	kaddr_t os_dict_entry_ptr, val = 0;
	dict_entry_t *os_dict_entries;
	uint32_t i, os_dict_cnt;

	if(kread_buf(os_dict + OS_DICTIONARY_COUNT_OFF, &os_dict_cnt, sizeof(os_dict_cnt)) == KERN_SUCCESS && os_dict_cnt != 0) {
		printf("os_dict_cnt: 0x%" PRIX32 "\n", os_dict_cnt);
		if(kread_addr(os_dict + OS_DICTIONARY_DICT_ENTRY_OFF, &os_dict_entry_ptr) == KERN_SUCCESS && os_dict_entry_ptr != 0) {
			printf("os_dict_entry_ptr: " KADDR_FMT "\n", os_dict_entry_ptr);
			if((os_dict_entries = kread_buf_alloc(os_dict_entry_ptr, os_dict_cnt * sizeof(*os_dict_entries))) != NULL) {
				for(i = 0; i < os_dict_cnt; ++i) {
					printf("key: " KADDR_FMT ", val: " KADDR_FMT "\n", os_dict_entries[i].key, os_dict_entries[i].val);
					if(os_dict_entries[i].key == key) {
						val = os_dict_entries[i].val;
						break;
					}
				}
				free(os_dict_entries);
			}
		}
	}
	return val;
}

static kern_return_t
sync_nonce(io_service_t nvram_serv) {
	if(IORegistryEntrySetCFProperty(nvram_serv, CFSTR("temp_key"), CFSTR("temp_val")) == KERN_SUCCESS && IORegistryEntrySetCFProperty(nvram_serv, CFSTR(kIONVRAMDeletePropertyKey), CFSTR("temp_key")) == KERN_SUCCESS) {
		return IORegistryEntrySetCFProperty(nvram_serv, CFSTR(kIONVRAMForceSyncNowPropertyKey), CFSTR(kBootNoncePropertyKey));
	}
	return KERN_FAILURE;
}

static void
dimentio(uint64_t nonce) {
	kaddr_t boot_nonce_os_symbol, of_dict, os_string, string_ptr;
	char nonce_hex[2 * sizeof(nonce) + sizeof("0x")];
	io_service_t nonce_serv, nvram_serv;

	if(find_task(getpid(), &our_task) == KERN_SUCCESS) {
		printf("our_task: " KADDR_FMT "\n", our_task);
		if((nonce_serv = get_serv("AppleMobileApNonce")) != IO_OBJECT_NULL) {
			printf("nonce_serv: 0x%" PRIX32 "\n", nonce_serv);
			if(nonce_generate(nonce_serv) == KERN_SUCCESS && get_boot_nonce_os_symbol(nonce_serv, &boot_nonce_os_symbol) == KERN_SUCCESS) {
				printf("boot_nonce_os_symbol: " KADDR_FMT "\n", boot_nonce_os_symbol);
				if((nvram_serv = get_serv("IODTNVRAM")) != IO_OBJECT_NULL) {
					printf("nvram_serv: 0x%" PRIX32 "\n", nvram_serv);
					if(get_of_dict(nvram_serv, &of_dict) == KERN_SUCCESS) {
						printf("of_dict: " KADDR_FMT "\n", of_dict);
						if((os_string = lookup_key_in_os_dict(of_dict, boot_nonce_os_symbol)) != 0) {
							printf("os_string: " KADDR_FMT "\n", os_string);
							if(kread_addr(os_string + OS_STRING_STRING_OFF, &string_ptr) == KERN_SUCCESS && string_ptr != 0) {
								printf("string_ptr: " KADDR_FMT "\n", string_ptr);
								snprintf(nonce_hex, sizeof(nonce_hex), "0x%016" PRIx64, nonce);
								if(kwrite_buf(string_ptr, nonce_hex, sizeof(nonce_hex)) == KERN_SUCCESS && sync_nonce(nvram_serv) == KERN_SUCCESS) {
									printf("Set nonce to 0x%016" PRIX64 "\n", nonce);
								}
							}
						}
					}
					IOObjectRelease(nvram_serv);
				}
			}
			IOObjectRelease(nonce_serv);
		}
	}
}

static void
entangle_nonce(uint64_t nonce, const void *key) {
	uint8_t entangled_nonce[CC_SHA384_DIGEST_LENGTH];
	uint64_t src[] = { 0, nonce }, dst[2];
	size_t i, out_sz;

	if(CCCrypt(kCCEncrypt, kCCAlgorithmAES128, 0, key, kCCKeySizeAES128, NULL, src, sizeof(src), dst, sizeof(dst), &out_sz) == kCCSuccess && out_sz == sizeof(dst)) {
		CC_SHA384(dst, sizeof(dst), entangled_nonce);
		printf("entangled_nonce: ");
		for(i = 0; i < sizeof(entangled_nonce); ++i) {
			printf("%02" PRIX8, entangled_nonce[i]);
		}
		putchar('\n');
	}
}

int
main(int argc, char **argv) {
	kaddr_t kbase, kslide;
	pfinder_t pfinder;
	uint32_t key[4];
	uint64_t nonce;

	if(argc >= 2 && sscanf(argv[1], "0x%016" PRIx64, &nonce) == 1) {
		if(init_tfp0() == KERN_SUCCESS) {
			printf("tfp0: 0x%" PRIX32 "\n", tfp0);
			if((kbase = get_kbase(&kslide)) != 0) {
				printf("kbase: " KADDR_FMT ", kslide: " KADDR_FMT "\n", kbase, kslide);
				if(pfinder_init(&pfinder, kbase) == KERN_SUCCESS) {
					if(pfinder_init_offsets(pfinder) == KERN_SUCCESS) {
						dimentio(nonce);
						if(argc == 3 && sscanf(argv[2], "0x%08" PRIX32 "%08" PRIX32 "%08" PRIX32 "%08" PRIX32, &(key[0]), &(key[1]), &(key[2]), &(key[3])) == 4) {
							entangle_nonce(nonce, key);
						}
					}
					pfinder_term(&pfinder);
				}
			}
			mach_port_deallocate(mach_task_self(), tfp0);
		}
	} else {
		printf("Usage: %s nonce [key_8a3]\n", argv[0]);
	}
}
