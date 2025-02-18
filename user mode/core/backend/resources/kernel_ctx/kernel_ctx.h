#pragma once
#include <windows.h>
#include <iostream>
#include <string_view>
#include <vector>
#include <thread>
#include <atomic>

#include "../util/util.h"
#include "../physmeme/physmeme.h"
#include "../util/hook.h"

#include <core/backend/skcrypt/skcrypter.h>

namespace riot
{
	//
	// offset of function into a physical page
	// used for comparing bytes when searching
	//
	inline std::uint16_t nt_PageOffset {};

	//
	// rva of nt function we are going to hook
	//
	inline std::uint32_t nt_rva {};

	//
	// base address of ntoskrnl (inside of this process)
	//
	inline const std::uint8_t* ntoskrnl_buffer {};

	//
	// has the page been found yet?
	//
	inline std::atomic<bool> is_page_found = false;

	//
	// mapping of a syscalls physical memory (for installing hooks)
	//
	inline std::atomic<void*> psyscall_func {};

	//
	// you can edit this how you choose, im hooking NtShutdownSystem.
	//
	inline const std::pair<std::string_view , std::string_view> syscall_hook = { "NtShutdownSystem" , "ntdll.dll" };

	class kernel_ctx
	{
	public:
		//
		// default constructor
		//
		kernel_ctx ( )
		{
			if ( psyscall_func.load ( ) || nt_PageOffset || ntoskrnl_buffer )
				return;

			nt_rva = reinterpret_cast< std::uint32_t >(
				util::get_kernel_export (
					encrypt( "ntoskrnl.exe" ) ,
					syscall_hook.first.data ( ) ,
					true
				) );

			nt_PageOffset = nt_rva % page_size;
			ntoskrnl_buffer = reinterpret_cast< std::uint8_t* >(
				LoadLibraryExA ( encrypt( "ntoskrnl.exe" ) , NULL , DONT_RESOLVE_DLL_REFERENCES ) );

			std::vector<std::thread> search_threads;
			//--- for each physical memory range, make a thread to search it
			for ( auto ranges : util::pmem_ranges )
				search_threads.emplace_back ( std::thread (
					&kernel_ctx::map_syscall ,
					this ,
					ranges.first ,
					ranges.second
				) );

			for ( std::thread& search_thread : search_threads )
				search_thread.join ( );
		}

		//
		// allocate kernel pool of desired size and type
		//
		void* allocate_pool ( std::size_t size , POOL_TYPE pool_type = NonPagedPool )
		{
			static const auto ex_alloc_pool =
				util::get_kernel_export (
					encrypt( "ntoskrnl.exe" ) ,
					encrypt( "ExAllocatePool" )
				);

			return syscall<ExAllocatePool> (
				ex_alloc_pool ,
				pool_type ,
				size
			);
		}

		void free_pool( void* pool_base )
		{
			static const auto ex_free_pool =
				util::get_kernel_export(
					encrypt( "ntoskrnl.exe" ) ,
					encrypt( "ExFreePool" )
				);

			syscall<ExFreePool>(
				ex_free_pool, 
				pool_base
			);
		}

		//
		// allocate kernel pool of size, pool tag, and type
		//
		//void* allocate_pool(std::size_t size, ULONG pool_tag = 'MEME', POOL_TYPE pool_type = NonPagedPool);
		void* allocate_pool ( std::size_t size , ULONG pool_tag = 'MEME' , POOL_TYPE pool_type = NonPagedPool )
		{
			static const auto ex_alloc_pool_with_tag =
				util::get_kernel_export (
					"ntoskrnl.exe" ,
					"ExAllocatePoolWithTag"
				);

			return syscall<ExAllocatePoolWithTag> (
				ex_alloc_pool_with_tag ,
				pool_type ,
				size ,
				pool_tag
			);
		}

		//
		// read kernel memory with RtlCopyMemory
		//
		void read_kernelraw ( void* addr , void* buffer , std::size_t size )
		{
			static const auto mm_copy_memory =
				util::get_kernel_export (
					"ntoskrnl.exe" ,
					"RtlCopyMemory"
				);

			syscall<decltype( &memcpy )> (
				mm_copy_memory ,
				buffer ,
				addr ,
				size
			);
		}

		//
		// write kernel memory with RtlCopyMemory
		//
		void write_kernelraw ( void* addr , void* buffer , std::size_t size )
		{
			static const auto mm_copy_memory =
				util::get_kernel_export (
					"ntoskrnl.exe" ,
					"RtlCopyMemory"
				);

			syscall<decltype( &memcpy )> (
				mm_copy_memory ,
				addr ,
				buffer ,
				size
			);
		}

		//
		// zero kernel memory using RtlZeroMemory
		//
		void zero_kernel_memory ( void* addr , std::size_t size )
		{
			static const auto rtl_zero_memory =
				util::get_kernel_export (
					"ntoskrnl.exe" ,
					"RtlZeroMemory"
				);

			syscall<decltype( &RtlSecureZeroMemory )> (
				rtl_zero_memory ,
				addr ,
				size
			);
		}

		//
		// clear piddb cache of a specific driver
		//
		bool clear_piddb_cache ( const std::string& file_name , const std::uint32_t timestamp )
		{
			static const auto piddb_lock =
				util::memory::get_piddb_lock ( );

			static const auto piddb_table =
				util::memory::get_piddb_table ( );

			if ( !piddb_lock || !piddb_table )
				return false;

			static const auto ex_acquire_resource =
				util::get_kernel_export (
					"ntoskrnl.exe" ,
					"ExAcquireResourceExclusiveLite"
				);

			static const auto lookup_element_table =
				util::get_kernel_export (
					"ntoskrnl.exe" ,
					"RtlLookupElementGenericTableAvl"
				);

			static const auto release_resource =
				util::get_kernel_export (
					"ntoskrnl.exe" ,
					"ExReleaseResourceLite"
				);

			static const auto delete_table_entry =
				util::get_kernel_export (
					"ntoskrnl.exe" ,
					"RtlDeleteElementGenericTableAvl"
				);

			if ( !ex_acquire_resource || !lookup_element_table || !release_resource )
				return false;

			PiDDBCacheEntry cache_entry;
			const auto drv_name = std::wstring ( file_name.begin ( ) , file_name.end ( ) );
			cache_entry.time_stamp = timestamp;
			RtlInitUnicodeString ( &cache_entry.driver_name , drv_name.data ( ) );

			//
			// ExAcquireResourceExclusiveLite
			//
			if ( !syscall<ExAcquireResourceExclusiveLite> ( ex_acquire_resource , piddb_lock , true ) )
				return false;

			//
			// RtlLookupElementGenericTableAvl
			//
			PIDCacheobj* found_entry_ptr =
				syscall<RtlLookupElementGenericTableAvl> (
					lookup_element_table ,
					piddb_table ,
					reinterpret_cast< void* >( &cache_entry )
				);

			if ( found_entry_ptr )
			{
				printf ( encrypt( " > piddb cache table : %p\n" ) , piddb_table );

				//
				// unlink entry.
				//
				PIDCacheobj found_entry = read_kernel<PIDCacheobj> ( found_entry_ptr );
				LIST_ENTRY NextEntry = read_kernel<LIST_ENTRY> ( found_entry.list.Flink );
				LIST_ENTRY PrevEntry = read_kernel<LIST_ENTRY> ( found_entry.list.Blink );

				PrevEntry.Flink = found_entry.list.Flink;
				NextEntry.Blink = found_entry.list.Blink;

				write_kernel<LIST_ENTRY> ( found_entry.list.Blink , PrevEntry );
				write_kernel<LIST_ENTRY> ( found_entry.list.Flink , NextEntry );

				//
				// delete entry.
				//
				syscall<RtlDeleteElementGenericTableAvl> ( delete_table_entry , piddb_table , found_entry_ptr );

				//
				// ensure the entry is 0
				//
				auto result = syscall<RtlLookupElementGenericTableAvl> (
					lookup_element_table ,
					piddb_table ,
					reinterpret_cast< void* >( &cache_entry )
				);

				syscall<ExReleaseResourceLite> ( release_resource , piddb_lock );
				return !result;
			}

			syscall<ExReleaseResourceLite> ( release_resource , piddb_lock );
			return false;
		}

		template <class T>
		T read_kernel ( void* addr )
		{
			if ( !addr )
				return {};
			T buffer;
			read_kernelraw ( addr , ( void* ) &buffer , sizeof ( T ) );
			return buffer;
		}

		template <class T>
		void write_kernel ( void* addr , const T& data )
		{
			if ( !addr )
				return;
			write_kernelraw ( addr , ( void* ) &data , sizeof ( T ) );
		}

		template <class T , class ... Ts>
		std::invoke_result_t<T , Ts...> syscall ( void* addr , Ts ... args ) const
		{
			static const auto proc =
				GetProcAddress (
					GetModuleHandleA ( "ntdll.dll" ) ,
					syscall_hook.first.data ( )
				);

			hook::make_hook ( psyscall_func , addr );
			auto result = reinterpret_cast< T >( proc )( args ... );
			hook::remove ( psyscall_func );
			return result;
		}

		//
		// find and map the physical page of a syscall into this process
		//
		void map_syscall ( std::uintptr_t begin , std::uintptr_t end ) const
		{
			//if the physical memory range is less then or equal to 2mb
			if ( begin + end <= 0x1000 * 512 )
			{
				auto page_va = riot::map_phys ( begin + nt_PageOffset , end );
				if ( page_va )
				{
					// scan every page of the physical memory range
					for ( auto page = page_va; page < page_va + end; page += 0x1000 )
					{
						if ( !is_page_found.load ( ) ) // keep scanning until its found
						{
							__try
							{
								if ( !memcmp ( reinterpret_cast< void* >( page ) , ntoskrnl_buffer + nt_rva , 32 ) )
								{
									//
									// this checks to ensure that the syscall does indeed work. if it doesnt, we keep looking!
									//
									psyscall_func.store ( ( void* ) page );
									auto my_proc_base = reinterpret_cast< std::uintptr_t >( GetModuleHandleA ( NULL ) );
									auto my_proc_base_from_syscall = reinterpret_cast< std::uintptr_t >( get_proc_base ( GetCurrentProcessId ( ) ) );

									if ( my_proc_base != my_proc_base_from_syscall )
										continue;

									is_page_found.store ( true );
									return;
								}
							}
							__except ( EXCEPTION_EXECUTE_HANDLER ) { }
						}
					}
					riot::unmap_phys ( page_va , end );
				}
			}
			else // else the range is bigger then 2mb
			{
				auto remainder = ( begin + end ) % ( 0x1000 * 512 );

				// loop over 2m chunks
				for ( auto range = begin; range < begin + end; range += 0x1000 * 512 )
				{
					auto page_va = riot::map_phys ( range + nt_PageOffset , 0x1000 * 512 );
					if ( page_va )
					{
						// loop every page of 2mbs (512)
						for ( auto page = page_va; page < page_va + 0x1000 * 512; page += 0x1000 )
						{
							if ( !is_page_found.load ( ) )
							{
								__try
								{
									if ( !memcmp ( reinterpret_cast< void* >( page ) , ntoskrnl_buffer + nt_rva , 32 ) )
									{
										//
										// this checks to ensure that the syscall does indeed work. if it doesnt, we keep looking!
										//
										psyscall_func.store ( ( void* ) page );
										auto my_proc_base = reinterpret_cast< std::uintptr_t >( GetModuleHandle ( NULL ) );
										auto my_proc_base_from_syscall = reinterpret_cast< std::uintptr_t >( get_proc_base ( GetCurrentProcessId ( ) ) );

										if ( my_proc_base != my_proc_base_from_syscall )
											continue;

										is_page_found.store ( true );
										return;
									}
								}
								__except ( EXCEPTION_EXECUTE_HANDLER ) { }
							}
						}
						riot::unmap_phys ( page_va , 0x1000 * 512 );
					}
				}

				// map the remainder and check each page of it
				auto page_va = riot::map_phys ( begin + end - remainder + nt_PageOffset , remainder );
				if ( page_va )
				{
					for ( auto page = page_va; page < page_va + remainder; page += 0x1000 )
					{
						if ( !is_page_found.load ( ) )
						{
							__try
							{
								if ( !memcmp ( reinterpret_cast< void* >( page ) , ntoskrnl_buffer + nt_rva , 32 ) )
								{
									//
									// this checks to ensure that the syscall does indeed work. if it doesnt, we keep looking!
									//
									psyscall_func.store ( ( void* ) page );
									auto my_proc_base = reinterpret_cast< std::uintptr_t >( GetModuleHandle ( NULL ) );
									auto my_proc_base_from_syscall = reinterpret_cast< std::uintptr_t >( get_proc_base ( GetCurrentProcessId ( ) ) );

									if ( my_proc_base != my_proc_base_from_syscall )
										continue;

									is_page_found.store ( true );
									return;
								}
							}
							__except ( EXCEPTION_EXECUTE_HANDLER ) { }
						}
					}
					riot::unmap_phys ( page_va , remainder );
				}
			}
		}

		//
		// used in conjunction with get_process_base.
		//
		PEPROCESS get_peprocess ( unsigned pid ) const
		{
			if ( !pid )
				return {};

			PEPROCESS proc;
			static auto get_peprocess_from_pid =
				util::get_kernel_export (
					"ntoskrnl.exe" ,
					"PsLookupProcessByProcessId"
				);

			syscall<PsLookupProcessByProcessId> (
				get_peprocess_from_pid ,
				( HANDLE ) pid ,
				&proc
			);
			return proc;
		}

		//
		// get base address of process (used to compare and ensure we find the right page).
		//
		void* get_proc_base ( unsigned pid ) const
		{
			if ( !pid )
				return  {};

			const auto peproc = get_peprocess ( pid );

			if ( !peproc )
				return {};

			static auto get_section_base =
				util::get_kernel_export (
					"ntoskrnl.exe" ,
					"PsGetProcessSectionBaseAddress"
				);

			return syscall<PsGetProcessSectionBaseAddress> (
				get_section_base ,
				peproc
			);
		}

	};
}