rule signature_46
{
	meta:
		author = "0xlsd"
		sample = "fe1c3d0d1709128590d6dd88bfe1929b6d2c13fb8a0b21b2fc5aa89811fecdd3"
	
	
	strings:
		$string_1 = {
			2B BA ?? ?? ?? ??
			2A 24 2B
			BA E3 E1 E5 BA
			7E ??
			2B BA ?? ?? ?? ??
			25 24 2B BA DB
			53
			92
			BA 2F 24 2B BA
			27
			24 2A
		}
	
	condition:
		any of them
	
}
