import "pe"

/*
Information on the Trojan BitCoin Miner variant found
		Num_of_Sections = 9
		packed_or_compressed = false
		imported_lib = "advapi32.dll, libcurl-4.dl1, kernel32.dll, msvcrt.dll, libwinpthread-1.dl1, user32.dll, ws2_32.dll"
		File_info = "Microsoft Visual C++ 8.0"
		md5 = "32AEFBD18068E0D796A7FF27D765ACC9"
		imphash = "5937457735cd3db7e0587fb31737d1d4"
		text_hash = "9E6E174C8CF7E9F7B4F3949B79A65B7B"
		data_hash = "CD92BB3AAC2C2D2B768AB9D0BC434030"
		rdata_hash = "191B0D0FFF86798167F5E8F8504B955B"
		pdata_hash = "DABC64CC8CE3EEFF35862D8F67EEA3B7"
		xdata_hash = "CFFE4F955874E3E36D57693311A84FBE"
		idata_hash = "02B410F8C7C9880E5E4A4E8D82010F08"
		CRT_hash = "187928B575D36590F7B9DEE9AD03CFA9"
		tls_hash = "0BA0EB6DA80BDA86CA4AD6D8A2EBBB56"
*/

rule BitCoinMiner_string {

	strings:
		$x1 = "{\"method\": \"login\", \"params\": {\"login\": \"%s\", \"pass\": \"%s\", \"agent\": \"cpuminer-multi/0.1\"}, \"id\": 1}" fullword ascii
		$x2 = "-x, --proxy=[PROTOCOL://]HOST[:PORT]  connect through a proxy" fullword ascii
      		$s3 = "-t, --threads=N       number of miner threads (default: number of processors)" fullword ascii
      		$s4 = "{\"method\": \"submit\", \"params\": {\"id\": \"%s\", \"job_id\": \"%s\", \"nonce\": \"%s\", \"result\": \"%s\"}, \"id\":1}" fullword ascii
      		$s5 = "\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\6666666666666666" fullword ascii
      		$s6 = "-P, --protocol-dump   verbose dump of protocol-level activities" fullword ascii
      		$s7 = "hash > target (false positive)" fullword ascii
      		$s8 = "User-Agent: cpuminer/2.3.3" fullword ascii
      		$s9 = "Failed to call rpc command after %i tries" fullword ascii
      		$s10 = "@hash <= target" fullword ascii
      		$s11 = "-O, --userpass=U:P    username:password pair for mining server" fullword ascii
      		$s12 = "%s: unsupported non-option argument '%s'" fullword ascii
      		$s13 = "-p, --pass=PASSWORD   password for mining server" fullword ascii
      		$s14 = "Tried to call rpc2 command before authentication" fullword ascii
      		$s15 = "{\"id\": 1, \"method\": \"mining.subscribe\", \"params\": [\"cpuminer/2.3.3\", \"%s\"]}" fullword ascii
      		$s16 = "JSON inval target" fullword ascii
      		$s17 = "JSON decode failed(%d): %s" fullword ascii
      		$s18 = "accepted: %lu/%lu (%.2f%%), %s khash/s %s" fullword ascii
      		$s19 = "%d miner threads started, using '%s' algorithm." fullword ascii
      		$s20 = "JSON decode of %s failed" fullword ascii
		
	
	condition:
		uint16(0) == 0x5a4d and filesize < 3000KB and ( 1 of ($x*) and 5 of ($s*) ) 
}

rule BitCoinMiner_imphash{
	condition:
		pe.imphash() == "5937457735cd3db7e0587fb31737d1d4"
}

rule BitCoinMiner_Num_Of_Sections{

	condition:
		pe.number_of_sections > 6 
}

rule BitCoinMiner_suspicious_imports_and_functions{
	condition:
		pe.imports("libcurl-4.dl1") and
		pe.imports("libwinpthread-1.dl1")
}

