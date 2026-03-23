#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <algorithm>
#include <cstdint>
#include "AlignedAlloc.h"
#include "MemoryFunction.h"

// clang-format off

#define BLOCK_ALIGN 0x10

#ifdef _WIN32
	#define MEMFUNC_USE_WIN32
#elif defined(__APPLE__)
	#include "TargetConditionals.h"
	#include <libkern/OSCacheControl.h>

	#if TARGET_OS_OSX
		#define MEMFUNC_USE_MMAP
		#define MEMFUNC_MMAP_ADDITIONAL_FLAGS (MAP_JIT)
		#if TARGET_CPU_ARM64
			#define MEMFUNC_MMAP_REQUIRES_JIT_WRITE_PROTECT
		#endif
	#else
		#define MEMFUNC_USE_MACHVM
		#if TARGET_OS_IPHONE
			#define MEMFUNC_MACHVM_STRICT_PROTECTION
		#endif
	#endif
#elif defined(__EMSCRIPTEN__)
	#include <emscripten.h>
	#define MEMFUNC_USE_WASM
#else
	#define MEMFUNC_USE_MMAP
#endif

#if defined(MEMFUNC_USE_WIN32)
#include <windows.h>
#elif defined(MEMFUNC_USE_MACHVM)
#include <mach/mach_init.h>
#include <mach/vm_map.h>
#include <sys/mman.h>
#if TARGET_OS_IPHONE
#include <signal.h>
#include <sys/ucontext.h>
#include <vector>
#include <mutex>
extern "C" int csops(int, unsigned int, void*, size_t);
static bool has_cs_debugged()
{
	int flags = 0;
	return !csops(0, 0 /*CS_OPS_STATUS*/, &flags, sizeof(flags)) && (flags & 0x10000000 /*CS_DEBUGGED*/);
}
#endif
#elif defined(MEMFUNC_USE_MMAP)
#include <sys/mman.h>
#include <pthread.h>
#elif defined(MEMFUNC_USE_WASM)
EM_JS_DEPS(WasmMemoryFunction, "$addFunction,$removeFunction");
EM_JS(int, WasmCreateFunction, (emscripten::EM_VAL moduleHandle),
{
	let module = Emval.toValue(moduleHandle);
	let moduleInstance = new WebAssembly.Instance(module, {
		env: {
			memory: wasmMemory,
			fctTable : Module.codeGenImportTable
		}
	});
	let fct = moduleInstance.exports.codeGenFunc;
	let fctId = addFunction(fct, 'vi');
	return fctId;
});
EM_JS(void, WasmDeleteFunction, (int fctId),
{
	removeFunction(fctId);
});
EM_JS(emscripten::EM_VAL, WasmCreateModule, (uintptr_t code, uintptr_t size),
{
	//var fs = require('fs');
	let moduleBytes = HEAP8.subarray(code, code + size);
	//fs.writeFileSync('module.wasm', moduleBytes);
	//{
	//	let bytesCopy = new Uint8Array(moduleBytes);
	//	let blob = new Blob([bytesCopy], { type: "binary/octet-stream" });
	//	let url = URL.createObjectURL(blob);
	//	console.log(url);
	//}
	let module = new WebAssembly.Module(moduleBytes);
	return Emval.toHandle(module);
});
#else
#error "No API to use for CMemoryFunction"
#endif

#if defined(MEMFUNC_USE_MACHVM) && TARGET_OS_IPHONE
// Simple pool allocator for iOS 26+ where each brk #0x69 is expensive.
// Allocates a large R-X region once, blessed by the debugger, with a
// R-W mirror for writing. Individual blocks are carved from the pool.
struct JitPool
{
	static constexpr size_t POOL_SIZE = 64 * 1024 * 1024;

	uint8_t* rx_base = nullptr;
	uint8_t* rw_base = nullptr;
	size_t   bump = 0;
	size_t   page_size = 0;
	bool     m_initialized = false;
	std::vector<std::pair<size_t, size_t>> free_list; // offset, size
	std::mutex mtx;

	void Init()
	{
		std::lock_guard<std::mutex> lock(mtx);
		if(m_initialized) return;

		vm_size_t ps = 0;
		host_page_size(mach_task_self(), &ps);
		page_size = ps;

		uint8_t* rx = (uint8_t*)mmap(nullptr, POOL_SIZE, PROT_READ | PROT_EXEC,
		                              MAP_ANON | MAP_PRIVATE, -1, 0);
		assert(rx != MAP_FAILED);

		// Notify the debugger about the executable region
		static volatile bool s_brk_trapped;
		static struct sigaction s_prev_trap;
		struct sigaction trap_act = {};
		trap_act.sa_sigaction = [](int, siginfo_t*, void* ctx) {
			s_brk_trapped = true;
			((ucontext_t*)ctx)->uc_mcontext->__ss.__pc += 4;
		};
		sigemptyset(&trap_act.sa_mask);
		trap_act.sa_flags = SA_SIGINFO;
		sigaction(SIGTRAP, &trap_act, &s_prev_trap);
		s_brk_trapped = false;
		__asm__ volatile(
			"mov x0, %0\nmov x1, %1\nbrk #0x69"
			:: "r"(rx), "r"((size_t)POOL_SIZE) : "x0", "x1", "memory");
		sigaction(SIGTRAP, &s_prev_trap, nullptr);

		vm_address_t rw_region = 0;
		vm_prot_t cur_prot = 0, max_prot = 0;
		kern_return_t kr = vm_remap(mach_task_self(), &rw_region, POOL_SIZE, 0,
			VM_FLAGS_ANYWHERE, mach_task_self(), (vm_address_t)rx,
			false, &cur_prot, &max_prot, VM_INHERIT_DEFAULT);
		assert(kr == KERN_SUCCESS);
		uint8_t* rw = (uint8_t*)rw_region;
		mprotect(rw, POOL_SIZE, PROT_READ | PROT_WRITE);

		rw_base = rw;
		rx_base = rx;
		m_initialized = true;
	}

	void* Alloc(size_t size, size_t& out_alloc_size)
	{
		static constexpr size_t ALLOC_ALIGN = 256;
		size_t aligned = ((size + ALLOC_ALIGN - 1) / ALLOC_ALIGN) * ALLOC_ALIGN;
		out_alloc_size = aligned;

		std::lock_guard<std::mutex> lock(mtx);
		// Check free list (first fit)
		for(auto it = free_list.begin(); it != free_list.end(); ++it)
		{
			if(it->second >= aligned)
			{
				size_t offset = it->first;
				if(it->second == aligned)
					free_list.erase(it);
				else
				{
					it->first += aligned;
					it->second -= aligned;
				}
				return rx_base + offset;
			}
		}
		// Bump allocate
		if(bump + aligned > POOL_SIZE) return nullptr;
		void* ptr = rx_base + bump;
		bump += aligned;
		return ptr;
	}

	void Free(void* ptr, size_t size)
	{
		if(!ptr || !rx_base) return;
		size_t offset = (uint8_t*)ptr - rx_base;
		std::lock_guard<std::mutex> lock(mtx);
		free_list.push_back({offset, size});
	}

	void* Writable(void* rx_ptr)
	{
		return rw_base + ((uint8_t*)rx_ptr - rx_base);
	}
};

static JitPool& getJitPool()
{
	static JitPool pool;
	return pool;
}
#endif

CMemoryFunction::CMemoryFunction()
: m_code(nullptr)
, m_size(0)
{

}

CMemoryFunction::CMemoryFunction(const void* code, size_t size)
: m_code(nullptr)
{
#if defined(MEMFUNC_USE_WIN32)
	m_size = size;
	m_code = framework_aligned_alloc(size, BLOCK_ALIGN);
	memcpy(m_code, code, size);
	
	DWORD oldProtect = 0;
	BOOL result = VirtualProtect(m_code, size, PAGE_EXECUTE_READWRITE, &oldProtect);
	assert(result == TRUE);
#elif defined(MEMFUNC_USE_MACHVM)
	vm_size_t page_size = 0;
	host_page_size(mach_task_self(), &page_size);
	size_t allocSize = ((size + page_size - 1) / page_size) * page_size;
#if TARGET_OS_IPHONE
	bool use_pool = false;
	if (__builtin_available(iOS 26, *))
		use_pool = has_cs_debugged();
	if (use_pool)
	{
		auto& pool = getJitPool();
		pool.Init();
		m_code = pool.Alloc(size, allocSize);
		assert(m_code != nullptr);
		m_writable = pool.Writable(m_code);
		memcpy(m_writable, code, size);
	}
	else
#endif
	{
		vm_allocate(mach_task_self(), reinterpret_cast<vm_address_t*>(&m_code), allocSize, TRUE);
		memcpy(m_code, code, size);
		vm_prot_t protection =
		#ifdef MEMFUNC_MACHVM_STRICT_PROTECTION
			VM_PROT_READ | VM_PROT_EXECUTE;
		#else
			VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE;
		#endif
		kern_return_t result = vm_protect(mach_task_self(), reinterpret_cast<vm_address_t>(m_code), size, 0, protection);
		assert(result == 0);
	}
	m_size = allocSize;
#elif defined(MEMFUNC_USE_MMAP)
	uint32 additionalMapFlags = 0;
	#ifdef MEMFUNC_MMAP_ADDITIONAL_FLAGS
		additionalMapFlags = MEMFUNC_MMAP_ADDITIONAL_FLAGS;
	#endif
	m_size = size;
	m_code = mmap(nullptr, size, PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS | additionalMapFlags, -1, 0);
	assert(m_code != MAP_FAILED);
#ifdef MEMFUNC_MMAP_REQUIRES_JIT_WRITE_PROTECT
	pthread_jit_write_protect_np(false);
#endif
	memcpy(m_code, code, size);
#ifdef MEMFUNC_MMAP_REQUIRES_JIT_WRITE_PROTECT
	pthread_jit_write_protect_np(true);
#endif
#elif defined(MEMFUNC_USE_WASM)
	m_wasmModule = emscripten::val::take_ownership(WasmCreateModule(reinterpret_cast<uintptr_t>(code), size));
	m_size = size;
	m_code = reinterpret_cast<void*>(WasmCreateFunction(m_wasmModule.as_handle()));
#endif
	ClearCache();
#if !defined(MEMFUNC_USE_WASM)
	assert((reinterpret_cast<uintptr_t>(m_code) & (BLOCK_ALIGN - 1)) == 0);
#endif
}

CMemoryFunction::~CMemoryFunction()
{
	Reset();
}

void CMemoryFunction::ClearCache()
{
#ifdef __APPLE__
	sys_icache_invalidate(m_code, m_size);
#elif defined(MEMFUNC_USE_MMAP)
	#if defined(__arm__) || defined(__aarch64__)
		__clear_cache(m_code, reinterpret_cast<uint8*>(m_code) + m_size);
	#endif
#endif
}

void CMemoryFunction::Reset()
{
	if(m_code != nullptr)
	{
#if defined(MEMFUNC_USE_WIN32)
		framework_aligned_free(m_code);
#elif defined(MEMFUNC_USE_MACHVM)
#if TARGET_OS_IPHONE
		if(m_writable)
		{
			getJitPool().Free(m_code, m_size);
		}
		else
#endif
		{
			vm_deallocate(mach_task_self(), reinterpret_cast<vm_address_t>(m_code), m_size);
		}
		m_writable = nullptr;
#elif defined(MEMFUNC_USE_MMAP)
		munmap(m_code, m_size);
#elif defined(MEMFUNC_USE_WASM)
		WasmDeleteFunction(reinterpret_cast<int>(m_code));
#endif
	}
	m_code = nullptr;
	m_size = 0;
#if defined(MEMFUNC_USE_WASM)
	m_wasmModule = emscripten::val();
#endif
}

bool CMemoryFunction::IsEmpty() const
{
	return m_code == nullptr;
}

CMemoryFunction& CMemoryFunction::operator =(CMemoryFunction&& rhs)
{
	Reset();
	std::swap(m_code, rhs.m_code);
	std::swap(m_writable, rhs.m_writable);
	std::swap(m_size, rhs.m_size);
#if defined(MEMFUNC_USE_WASM)
	std::swap(m_wasmModule, rhs.m_wasmModule);
#endif
	return (*this);
}

void CMemoryFunction::operator()(void* context)
{
	typedef void (*FctType)(void*);
	auto fct = reinterpret_cast<FctType>(m_code);
	fct(context);
}

void* CMemoryFunction::GetCode() const
{
	return m_code;
}

void* CMemoryFunction::GetWritableCode() const
{
	return m_writable ? m_writable : m_code;
}

size_t CMemoryFunction::GetSize() const
{
	return m_size;
}

void CMemoryFunction::BeginModify()
{
#if defined(MEMFUNC_USE_MACHVM) && defined(MEMFUNC_MACHVM_STRICT_PROTECTION)
	if(!m_writable)
	{
		kern_return_t result = vm_protect(mach_task_self(), reinterpret_cast<vm_address_t>(m_code), m_size, 0, VM_PROT_READ | VM_PROT_WRITE);
		assert(result == 0);
	}
	// When dual-mapped, m_writable is always writable
#elif defined(MEMFUNC_USE_MMAP) && defined(MEMFUNC_MMAP_REQUIRES_JIT_WRITE_PROTECT)
	pthread_jit_write_protect_np(false);
#endif
}

void CMemoryFunction::EndModify()
{
#if defined(MEMFUNC_USE_MACHVM) && defined(MEMFUNC_MACHVM_STRICT_PROTECTION)
	if(!m_writable)
	{
		kern_return_t result = vm_protect(mach_task_self(), reinterpret_cast<vm_address_t>(m_code), m_size, 0, VM_PROT_READ | VM_PROT_EXECUTE);
		assert(result == 0);
	}
#elif defined(MEMFUNC_USE_MMAP) && defined(MEMFUNC_MMAP_REQUIRES_JIT_WRITE_PROTECT)
	pthread_jit_write_protect_np(true);
#endif
	ClearCache();
}

CMemoryFunction CMemoryFunction::CreateInstance()
{
#if defined(MEMFUNC_USE_WASM)
	CMemoryFunction result;
	result.m_wasmModule = m_wasmModule;
	result.m_size = m_size;
	result.m_code = reinterpret_cast<void*>(WasmCreateFunction(m_wasmModule.as_handle()));
	return result;
#else
	return CMemoryFunction(GetCode(), GetSize());
#endif
}
