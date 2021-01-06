rule signature_57
{
	meta:
		author = "0xlsd"
		sample = "1e5e3fd25551b3fc66fe6eb663f4122a499303d30cc81edb42bead3ef1ea51ed"
	
	
	strings:
		$string_1 = {
			15 8B FF D5 75
			8B 84 D9 ?? ?? ?? ??
			0C 8B
			84 D9
			15 8B E6 FB 3F
			8B 84 D9 ?? ?? ?? ??
			6E
			8B 84 D9 ?? ?? ?? ??
		}
	
	condition:
		any of them
	
}
