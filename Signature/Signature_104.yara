rule signature_104
{
	meta:
		author = "0xlsd"
		sample = "a286609928f6e91062fb7a47970dcb2b3edea904cb2cc5f000caa3509e03a4be"
	
	
	strings:
		$string_1 = {
			20 72 ??
			6E
			20 69 ??
			20 44 4F ??
			20 6D ??
			64 65 2E 0D 0D 0A 24 00
			00 00
			00 00
			00 00
			72 ??
			77 ??
			36 A3 ?? ?? ?? ??
		}
	
	condition:
		any of them
	
}
