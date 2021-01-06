rule signature_75
{
	meta:
		author = "0xlsd"
		sample = "c0de47c1a5d6ee3d1a687fb95ef3340496178f8d301257c11781a90804524c0d"
	
	
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
			31 B8 ?? ?? ?? ??
		}
	
	condition:
		any of them
	
}
