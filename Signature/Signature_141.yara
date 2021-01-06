rule signature_141
{
	meta:
		author = "0xlsd"
		sample = "5f4346f63e8fe3d5f74dbe4942b9dc43304a0386b10a806e3fa1f5aafbbb1d1a"
	
	
	strings:
		$string_1 = {
			CF
			81 F9 38 CE 81 4B
			38 CF
			81 96 ?? ?? ?? ?? 38 CF 81 7A
			24 C1
			81 F8 38 CF 81 E7
			6A 45
			81 F7 38 CF 81 E7
			6A 5B
		}
	
	condition:
		any of them
	
}
