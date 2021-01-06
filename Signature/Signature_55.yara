rule signature_55
{
	meta:
		author = "0xlsd"
		sample = "50bd6ddda057f39413c3476cb92667bf8b0540fb0040ed63d220131bd0234084"
	
	
	strings:
		$string_1 = {
			58
			F6 B2 ?? ?? ?? ??
			BA 58 F6 B2 A5
			52
			F6 C3 BA
			58
			F6 5E ??
			56
			F6 D3
			BA 58 F6 BF A5
			4B
			F6 D4
			BA 58 F6 DD BA
			59
			F6 E0
		}
	
	condition:
		any of them
	
}
