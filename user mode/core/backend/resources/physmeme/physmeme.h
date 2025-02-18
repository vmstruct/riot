#pragma once
#include <windows.h>
#include <cstdint>

#include "../util/util.h"
#include "../loadup.h"
#include "../raw_driver.h"

#include <core/backend/skcrypt/skcrypter.h>

#define MAP_PHYSICAL 0xC3502004
#define UNMAP_PHYSICAL 0xC3502008

#pragma pack ( push, 1 )
typedef struct _GIOMAP
{
	unsigned long	interface_type;
	unsigned long	bus;
	std::uintptr_t  physical_address;
	unsigned long	io_space;
	unsigned long	size;
} GIOMAP;
#pragma pack ( pop )

namespace riot
{
	inline std::string drv_key;
	inline HANDLE drv_handle = NULL;

	__forceinline bool load_drv ( )
	{
		const auto [result , key] =
			service::load (
				raw_driver_bytes ,
				sizeof ( raw_driver_bytes )
			);

		auto encr_GIO = ( encrypt ( "\\\\.\\GIO" ) );
		drv_key = key;
		drv_handle = CreateFileA (
			encr_GIO ,
			GENERIC_READ | GENERIC_WRITE ,
			NULL ,
			NULL ,
			OPEN_EXISTING ,
			FILE_ATTRIBUTE_NORMAL ,
			NULL
		);

		encr_GIO;

		return drv_handle;
	}

	__forceinline bool unload_drv ( )
	{
		return CloseHandle ( drv_handle ) && service::unload ( drv_key );
	}

	__forceinline std::uintptr_t map_phys ( std::uintptr_t addr , std::size_t size )
	{
		//--- ensure the validity of the address we are going to try and map
		if ( !util::is_valid ( addr ) )
			return NULL;

		GIOMAP in_buffer = { 0, 0, addr, 0, size };
		uintptr_t out_buffer[ 2 ] = { 0 };
		unsigned long returned = 0;

		if ( !DeviceIoControl (
			drv_handle ,
			MAP_PHYSICAL ,
			reinterpret_cast< LPVOID >( &in_buffer ) ,
			sizeof ( in_buffer ) ,
			reinterpret_cast< LPVOID >( out_buffer ) ,
			sizeof ( out_buffer ) ,
			&returned , NULL
		) )
			return NULL;

		return out_buffer[ 0 ];
	}

	__forceinline bool unmap_phys ( std::uintptr_t addr , std::size_t size )
	{
		uintptr_t in_buffer = addr;
		uintptr_t out_buffer[ 2 ] = { sizeof ( out_buffer ) };
		unsigned long returned = NULL;

		return DeviceIoControl (
			drv_handle ,
			UNMAP_PHYSICAL ,
			reinterpret_cast< LPVOID >( &in_buffer ) ,
			sizeof ( in_buffer ) ,
			reinterpret_cast< LPVOID >( out_buffer ) ,
			sizeof ( out_buffer ) ,
			&returned , NULL
		);
	}
}