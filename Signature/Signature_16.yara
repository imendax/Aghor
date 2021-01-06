rule signature_16
{
	meta:
		author = "0xlsd"
		sample = "3ec616809714c510e751a222310f8b61b86636924ca02c9b2eb621d9aec4a9d8"
	
	
	strings:
		$string_1 = {
			90
			78 ??
			48
			30 18
			00 E8
			D0 B8 ?? ?? ?? ??
			40
			28 10
			F8
			E0 C8
			B0 98
			80 68 ?? 38
			20 08
		}
	
	condition:
		any of them
	
}
